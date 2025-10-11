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
	r    bufio.Scanner
	line []byte
}

func (r *lineReader) Read(buf []byte) (int, error) {
	for len(r.line) == 0 {
		if !r.r.Scan() {
			if err := r.r.Err(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		line := r.r.Bytes()
		if bytes.HasPrefix(line, []byte("-")) {
			continue
		}
		r.line = line
	}
	n := copy(buf, r.line)
	r.line = r.line[n:]
	return n, nil
}

type PasswordCache map[[SaltSize]byte][]byte

func decryptBinary(w io.Writer, r io.Reader, password string, pwCache PasswordCache) error {
	header := make([]byte, 1+SaltSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	salt := header[1:]
	key, ok := pwCache[[SaltSize]byte(salt)]
	if !ok {
		var err error
		key, err = HashPassword(password, salt)
		if err != nil {
			return err
		}
		pwCache[[SaltSize]byte(salt)] = key
	}
	reader := newDecryptingReader(r, key)
	_, err := io.Copy(w, reader)
	return err
}

func Decrypt(w io.Writer, r io.Reader, password string, pwCache PasswordCache) error {
	bufReader := bufio.NewReaderSize(r, 1)
	b, err := bufReader.Peek(1)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("no input")
		}
		return err
	}
	if b[0] == 0 {
		return decryptBinary(w, bufReader, password, pwCache)
	}
	if b[0] != '-' {
		return errors.New("invalid input")
	}
	return decryptBinary(w, base64.NewDecoder(base64.StdEncoding, &lineReader{r: *bufio.NewScanner(bufReader)}), password, pwCache)
}

func DecryptFile(fileName, password string, pwCache PasswordCache) (err error) {
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
	if err := Decrypt(fOut, fIn, password, pwCache); err != nil {
		return err
	}
	return fOut.Close()
}
