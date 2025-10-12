package sym

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
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
	header := make([]byte, len(magic))
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if !bytes.Equal(header, []byte(magic)) {
		return fmt.Errorf("bad file format")
	}
	_, err := io.Copy(w, newDecryptingReader(r, password))
	return err
}

func decrypt(w io.Writer, r io.Reader, password string) error {
	bufReader := bufio.NewReaderSize(r, 81)
	b, err := bufReader.Peek(1)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("no input")
		}
		return err
	}
	if b[0] == 0x80 {
		return decryptBinary(w, bufReader, password)
	}
	if b[0] != '-' {
		return errors.New("invalid input")
	}
	_, err = io.Copy(w, newDecryptingReader(base64.NewDecoder(base64.StdEncoding, &lineReader{r: bufReader}), password))
	return err
}

type DecryptOptions struct {
	password string
	force    bool

	stdin  io.Reader
	stdout io.Writer
}

var DefaultDecryptOptions = DecryptOptions{
	stdin:  os.Stdin,
	stdout: os.Stdout,
}

func (o *DecryptOptions) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.password, "p", "", "use the specified password; if not provided, dec will prompt for a password")
	fs.BoolVar(&o.force, "f", false, "overwrite output files even if they already exist")
}

func (o *DecryptOptions) decryptFile(fileName string, password string) (err error) {
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
	fileOpts := os.O_CREATE | os.O_WRONLY
	if o.force {
		fileOpts |= os.O_TRUNC
	} else {
		fileOpts |= os.O_EXCL
	}
	fOut, err := os.OpenFile(outFileName, fileOpts, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file %q exists (use -f to overwrite)", outFileName)
		}
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if err := decrypt(fOut, fIn, password); err != nil {
		return fmt.Errorf("decrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (o *DecryptOptions) Run(args ...string) error {
	if len(args) == 0 && o.password == "" {
		return fmt.Errorf("-p is required when reading from stdin")
	}
	var password string
	if o.password != "" {
		password = o.password
	} else {
		var err error
		password, err = readPassword()
		if err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return decrypt(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := o.decryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}
