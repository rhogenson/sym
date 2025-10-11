package sym

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type lineReader struct {
	r    *bufio.Reader
	line []byte
}

func (r *lineReader) Read(buf []byte) (int, error) {
	for len(r.line) == 0 {
		line, err := r.r.ReadBytes('\n')
		if len(line) == 0 {
			return 0, err
		}
		if bytes.HasPrefix(line, []byte("-")) {
			continue
		}
		r.line = bytes.TrimSuffix(line, []byte("\n"))
	}
	n := copy(buf, r.line)
	r.line = r.line[n:]
	return n, nil
}

func decryptBinary(w io.Writer, r io.Reader, password string) error {
	header := make([]byte, 1)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	reader := newDecryptingReader(r, password)
	_, err := io.Copy(w, reader)
	return err
}

func Decrypt(w io.Writer, r io.Reader, password string) error {
	bufReader := bufio.NewReaderSize(r, 81)
	b, err := bufReader.Peek(1)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("no input")
		}
		return err
	}
	if b[0] == 0 {
		return decryptBinary(w, bufReader, password)
	}
	if b[0] != '-' {
		return errors.New("invalid input")
	}
	return decryptBinary(w, base64.NewDecoder(base64.StdEncoding, &lineReader{r: bufReader}), password)
}

func DecryptFile(fileName string, password string) (err error) {
	var outFileName string
	if name, ok := strings.CutSuffix(fileName, ".enc"); ok {
		outFileName = name
	} else if name, ok := strings.CutSuffix(fileName, ".enc.txt"); ok {
		outFileName = name
	} else {
		outFileName = fileName + ".dec"
	}
	fIn, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer fIn.Close()
	fOut, err := os.Create(outFileName)
	if err != nil {
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if err := Decrypt(fOut, fIn, password); err != nil {
		return err
	}
	return fOut.Close()
}
