package sym

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	nonceSize    = 12
	aeadOverhead = 16

	encryptedSegmentSize = 1024 * 1024
	plaintextSegmentSize = encryptedSegmentSize - aeadOverhead

	saltSize = 32
)

type segmentEncrypter struct {
	password string

	aead  cipher.AEAD
	nonce [nonceSize]byte
}

func (se *segmentEncrypter) initialize(salt []byte) error {
	key, err := hashPassword(se.password, salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	se.aead, err = cipher.NewGCM(block)
	return err
}

func (se *segmentEncrypter) ad(lastSegment bool) ([]byte, error) {
	// Increment counter
	for i := 0; ; i++ {
		if i == len(se.nonce) {
			return nil, errors.New("counter overflowed")
		}
		se.nonce[i]++
		if se.nonce[i] != 0 {
			break
		}
	}
	ad := make([]byte, len(se.nonce)+1)
	copy(ad, se.nonce[:])
	if lastSegment {
		ad[len(ad)-1] = 1
	}
	return ad, nil
}

func (se *segmentEncrypter) encrypt(out, buf []byte, lastSegment bool) ([]byte, error) {
	ad, err := se.ad(lastSegment)
	if err != nil {
		return nil, err
	}
	return se.aead.Seal(out, se.nonce[:], buf, ad), nil
}

func (se *segmentEncrypter) decrypt(out, buf []byte, lastSegment bool) ([]byte, error) {
	ad, err := se.ad(lastSegment)
	if err != nil {
		return nil, err
	}
	return se.aead.Open(out, se.nonce[:], buf, ad)
}

type encryptingWriter struct {
	w           io.Writer
	encrypter   segmentEncrypter
	buf         []byte
	initialized bool
}

func newEncryptingWriter(w io.Writer, password string) *encryptingWriter {
	return &encryptingWriter{
		w: w,
		encrypter: segmentEncrypter{
			password: password,
		},
	}
}

func (w *encryptingWriter) initialize() error {
	if w.initialized {
		return nil
	}
	header := make([]byte, saltSize)
	rand.Read(header)
	if err := w.encrypter.initialize(header); err != nil {
		return err
	}
	if _, err := w.w.Write(header); err != nil {
		return err
	}
	w.buf = make([]byte, 0, encryptedSegmentSize)
	w.initialized = true
	return nil
}

func (w *encryptingWriter) writeBuf(lastSegment bool) error {
	var err error
	if w.buf, err = w.encrypter.encrypt(w.buf[:0], w.buf, lastSegment); err != nil {
		return err
	}
	if _, err := w.w.Write(w.buf); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

func (w *encryptingWriter) Write(buf []byte) (int, error) {
	if err := w.initialize(); err != nil {
		return 0, err
	}
	nn := 0
	for len(buf) > 0 {
		if len(w.buf) == plaintextSegmentSize {
			if err := w.writeBuf(false); err != nil {
				return nn, err
			}
		}
		n := copy(w.buf[len(w.buf):plaintextSegmentSize], buf)
		nn += n
		w.buf = w.buf[:len(w.buf)+n]
		buf = buf[n:]
	}
	return nn, nil
}

func (w *encryptingWriter) Close() error {
	if err := w.initialize(); err != nil {
		return err
	}
	return w.writeBuf(true)
}

type decryptingReader struct {
	r           *bufio.Reader
	decrypter   segmentEncrypter
	buf         bytes.Buffer
	initialized bool
}

func newDecryptingReader(r io.Reader, password string) *decryptingReader {
	return &decryptingReader{
		r: bufio.NewReaderSize(r, 1),
		decrypter: segmentEncrypter{
			password: password,
		},
	}
}

func (r *decryptingReader) initialize() error {
	if r.initialized {
		return nil
	}
	header := make([]byte, saltSize)
	if _, err := io.ReadFull(r.r, header); err != nil {
		return err
	}
	if err := r.decrypter.initialize(header); err != nil {
		return err
	}
	r.buf = *bytes.NewBuffer(make([]byte, 0, encryptedSegmentSize))
	r.initialized = true
	return nil
}

func (r *decryptingReader) fillBuf() error {
	r.buf.Reset()
	buf := r.buf.AvailableBuffer()[:encryptedSegmentSize]
	n, err := io.ReadFull(r.r, buf)
	if n == 0 {
		return err
	}
	buf = buf[:n]
	_, readErr := r.r.Peek(1)
	buf, err = r.decrypter.decrypt(buf[:0], buf, readErr == io.EOF)
	if err != nil {
		return err
	}
	r.buf.Write(buf)
	return nil
}

func (r *decryptingReader) Read(buf []byte) (int, error) {
	if err := r.initialize(); err != nil {
		return 0, err
	}
	if r.buf.Len() == 0 {
		if err := r.fillBuf(); err != nil {
			return 0, err
		}
	}
	return r.buf.Read(buf)
}
