package sym

import (
	"bufio"
	"encoding/base64"
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

func Encrypt(w io.Writer, r io.Reader, password string) error {
	if _, err := w.Write([]byte{0}); err != nil {
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
	if err := Encrypt(base64Writer, r, password); err != nil {
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

func EncryptFile(fileName string, password string, asciiOutput bool) (err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	ext := ".enc"
	if asciiOutput {
		ext = ".enc.txt"
	}
	fOut, err := os.Create(fileName + ext)
	if err != nil {
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if asciiOutput {
		err = EncryptBase64(fOut, f, password)
	} else {
		err = Encrypt(fOut, f, password)
	}
	if err != nil {
		return err
	}
	return fOut.Close()
}
