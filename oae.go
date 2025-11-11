package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceSize    = chacha20poly1305.NonceSize
	aeadOverhead = chacha20poly1305.Overhead

	segmentSize          = 1024 * 1024
	plaintextSegmentSize = segmentSize - aeadOverhead

	saltSize = 32
)

type segmentEncrypter struct {
	password string

	aead  cipher.AEAD
	nonce [nonceSize]byte
}

func (se *segmentEncrypter) initialize(salt []byte) error {
	key := hashPassword(se.password, salt)
	var err error
	se.aead, err = chacha20poly1305.New(key)
	return err
}

func (se *segmentEncrypter) ad(lastSegment bool) []byte {
	// Increment counter
	for i := 0; ; i++ {
		if i == len(se.nonce) {
			panic("counter overflowed")
		}
		se.nonce[i]++
		if se.nonce[i] != 0 {
			break
		}
	}
	if lastSegment {
		return []byte{1}
	}
	return []byte{0}
}

func (se *segmentEncrypter) encrypt(out, buf []byte, lastSegment bool) []byte {
	ad := se.ad(lastSegment)
	return se.aead.Seal(out, se.nonce[:], buf, ad)
}

func (se *segmentEncrypter) decrypt(out, buf []byte, lastSegment bool) ([]byte, error) {
	ad := se.ad(lastSegment)
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
	w.buf = make([]byte, 0, segmentSize)
	w.initialized = true
	return nil
}

func (w *encryptingWriter) writeBuf(lastSegment bool) error {
	if _, err := w.w.Write(w.encrypter.encrypt(w.buf[:0], w.buf, lastSegment)); err != nil {
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

func (w *encryptingWriter) close() error {
	if err := w.initialize(); err != nil {
		return err
	}
	return w.writeBuf(true)
}

func (w *encryptingWriter) ReadFrom(r io.Reader) (int64, error) {
	if err := w.initialize(); err != nil {
		return 0, err
	}
	var nn int64
	for {
		n, err := io.ReadFull(r, w.buf[len(w.buf):plaintextSegmentSize+1])
		nn += int64(n)
		w.buf = w.buf[:len(w.buf)+n]
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nn, nil
			}
			return nn, err
		}
		nextByte := w.buf[plaintextSegmentSize]
		w.buf = w.buf[:plaintextSegmentSize]
		if err := w.writeBuf(false); err != nil {
			return nn, err
		}
		w.buf = w.buf[:1]
		w.buf[0] = nextByte
	}
}

type decryptingReader struct {
	r              *bufio.Reader
	decrypter      segmentEncrypter
	buf            bytes.Buffer
	initialized    bool
	readFinalBlock bool
}

func newDecryptingReader(r io.Reader, password string) *decryptingReader {
	return &decryptingReader{
		r: bufio.NewReaderSize(r, 0), // we only need .UnreadByte
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
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if err := r.decrypter.initialize(header); err != nil {
		return err
	}
	r.buf = *bytes.NewBuffer(make([]byte, 0, segmentSize+1))
	r.initialized = true
	return nil
}

func (r *decryptingReader) fillBuf() error {
	r.buf.Reset()
	// Read 1 extra byte to make sure if we're at EOF.
	buf := r.buf.AvailableBuffer()[:segmentSize+1]
	n, err := io.ReadFull(r.r, buf)
	if err == io.ErrUnexpectedEOF {
		r.readFinalBlock = true
	} else if err != nil {
		if err == io.EOF && !r.readFinalBlock {
			return errors.New("premature EOF")
		}
		return err
	}
	buf = buf[:n]
	if len(buf) == int(segmentSize)+1 {
		r.r.UnreadByte()
		buf = buf[:segmentSize]
	}
	buf, err = r.decrypter.decrypt(buf[:0], buf, r.readFinalBlock)
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

func (r *decryptingReader) WriteTo(w io.Writer) (int64, error) {
	if err := r.initialize(); err != nil {
		return 0, err
	}
	var nn int64
	for {
		n, err := r.buf.WriteTo(w)
		nn += n
		if err != nil {
			return nn, err
		}
		if err := r.fillBuf(); err != nil {
			if err == io.EOF {
				return nn, nil
			}
			return nn, err
		}
	}
}
