package sym

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const (
	nonceSize       = 12
	aeadOverhead    = 16
	noncePrefixSize = nonceSize - 8

	segmentSize          = 4 * 1024 * 1024
	encryptedSegmentSize = segmentSize + aeadOverhead
)

type segmentEncrypter struct {
	key         []byte
	noncePrefix [noncePrefixSize]byte

	aead cipher.AEAD
	i    uint64
}

func (se *segmentEncrypter) initialize() error {
	block, err := aes.NewCipher(se.key)
	if err != nil {
		return err
	}
	se.aead, err = cipher.NewGCM(block)
	return err
}

func (se *segmentEncrypter) nonce(lastSegment bool) ([]byte, []byte, error) {
	if se.i == math.MaxUint64 {
		return nil, nil, errors.New("counter overflowed")
	}
	nonce := make([]byte, nonceSize)
	copy(nonce, se.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], se.i)
	ad := make([]byte, 9)
	binary.BigEndian.PutUint64(ad, se.i)
	if lastSegment {
		ad[8] = 1
	}
	se.i++
	return nonce, ad, nil
}

func (se *segmentEncrypter) encrypt(out, buf []byte, lastSegment bool) ([]byte, error) {
	nonce, ad, err := se.nonce(lastSegment)
	if err != nil {
		return nil, err
	}
	return se.aead.Seal(out, nonce, buf, ad), nil
}

func (se *segmentEncrypter) decrypt(out, buf []byte, lastSegment bool) ([]byte, error) {
	nonce, ad, err := se.nonce(lastSegment)
	if err != nil {
		return nil, err
	}
	return se.aead.Open(out, nonce, buf, ad)
}

type encryptingWriter struct {
	w           io.Writer
	encrypter   segmentEncrypter
	buf         []byte
	initialized bool
}

func newEncryptingWriter(w io.Writer, key []byte, noncePrefix [noncePrefixSize]byte) *encryptingWriter {
	return &encryptingWriter{
		w: w,
		encrypter: segmentEncrypter{
			key:         key,
			noncePrefix: noncePrefix,
		},
	}
}

func (w *encryptingWriter) initialize() error {
	if w.initialized {
		return nil
	}
	if err := w.encrypter.initialize(); err != nil {
		return err
	}
	if _, err := w.w.Write(w.encrypter.noncePrefix[:]); err != nil {
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
		if len(w.buf) == segmentSize {
			if err := w.writeBuf(false); err != nil {
				return nn, err
			}
		}
		n := copy(w.buf[len(w.buf):segmentSize], buf)
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

func newDecryptingReader(r io.Reader, key []byte) *decryptingReader {
	return &decryptingReader{
		r: bufio.NewReaderSize(r, 1),
		decrypter: segmentEncrypter{
			key: key,
		},
	}
}

func (r *decryptingReader) initialize() error {
	if r.initialized {
		return nil
	}
	if _, err := io.ReadFull(r.r, r.decrypter.noncePrefix[:]); err != nil {
		return err
	}
	if err := r.decrypter.initialize(); err != nil {
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
		if err == io.ErrUnexpectedEOF {
			return io.EOF
		}
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
