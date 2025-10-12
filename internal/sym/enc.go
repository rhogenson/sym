package sym

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

type newlineWriter struct {
	w *bufio.Writer
	n int
}

func (w *newlineWriter) Write(buf []byte) (int, error) {
	const lineSize = 80
	nn := 0
	for len(buf) > 0 {
		if w.n == lineSize {
			if err := w.w.WriteByte('\n'); err != nil {
				return nn, err
			}
			w.n = 0
		}
		n, err := w.w.Write(buf[:min(lineSize-w.n, len(buf))])
		nn += n
		buf = buf[n:]
		w.n += n
		if err != nil {
			return nn, err
		}
	}
	return nn, nil
}

func EncryptBinary(w io.Writer, r io.Reader, password string) error {
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	writer := newEncryptingWriter(w, password)
	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	return writer.Close()
}

func EncryptBase64(w io.Writer, r io.Reader, password string) error {
	bufWriter := bufio.NewWriter(w)
	if _, err := bufWriter.WriteString(`-------------------------- Begin encrypted text block --------------------------
-------------------------- am i cool like gpg? ---------------------------------
`); err != nil {
		return err
	}
	base64Writer := base64.NewEncoder(base64.StdEncoding, &newlineWriter{w: bufWriter})
	encryptingWriter := newEncryptingWriter(base64Writer, password)
	if _, err := io.Copy(encryptingWriter, r); err != nil {
		return err
	}
	if err := encryptingWriter.Close(); err != nil {
		return err
	}
	if err := base64Writer.Close(); err != nil {
		return err
	}
	if err := bufWriter.WriteByte('\n'); err != nil {
		return err
	}
	return bufWriter.Flush()
}

type encryptOptions struct {
	asciiOutput bool
	force       bool
}

type EncryptFileOption interface {
	encryptOpt(*encryptOptions)
}

type encryptFileOptionFunc func(*encryptOptions)

func (f encryptFileOptionFunc) encryptOpt(opts *encryptOptions) { f(opts) }

func WithASCIIOutput(asciiOutput bool) EncryptFileOption {
	return encryptFileOptionFunc(func(opts *encryptOptions) {
		opts.asciiOutput = asciiOutput
	})
}

func EncryptFile(fileName string, password string, options ...EncryptFileOption) (err error) {
	opts := new(encryptOptions)
	for _, o := range options {
		o.encryptOpt(opts)
	}

	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	ext := ".enc"
	if opts.asciiOutput {
		ext = ".enc.txt"
	}
	fileOpts := os.O_CREATE | os.O_WRONLY
	if opts.force {
		fileOpts |= os.O_TRUNC
	} else {
		fileOpts |= os.O_EXCL
	}
	fOut, err := os.OpenFile(fileName+ext, fileOpts, 0644)
	if err != nil {
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if opts.asciiOutput {
		err = EncryptBase64(fOut, f, password)
	} else {
		err = EncryptBinary(fOut, f, password)
	}
	if err != nil {
		return fmt.Errorf("encrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}
