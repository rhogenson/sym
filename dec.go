package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func (o *decryptOptions) decrypt(w io.Writer, r io.Reader, password string) error {
	_, err := io.Copy(w, newDecryptingReader(r, password, o.iterations))
	return err
}

type decryptFlags struct {
	password string
	force    bool
}

func (f *decryptFlags) registerFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.password, "p", "", "use the specified password; if not provided, dec will prompt for a password")
	fs.BoolVar(&f.force, "f", false, "overwrite output files even if they already exist")
}

type decryptOptions struct {
	decryptFlags

	iterations int
	passwordIn func() (string, error)
	stdin      io.Reader
	stdout     io.Writer
}

var defaultDecryptOptions = decryptOptions{
	iterations: defaultPBKDF2Iters,
	passwordIn: termReadPassword,
	stdin:      os.Stdin,
	stdout:     os.Stdout,
}

func (o *decryptOptions) decryptFile(fileName string, password string) (err error) {
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
	if err := o.decrypt(fOut, fIn, password); err != nil {
		return fmt.Errorf("decrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (o *decryptOptions) readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter password: ")
	pw, err := o.passwordIn()
	fmt.Fprintln(os.Stderr)
	return pw, err
}

func (o *decryptOptions) run(args ...string) error {
	if len(args) == 0 && o.password == "" {
		return fmt.Errorf("-p is required when reading from stdin")
	}
	var password string
	if o.password != "" {
		password = o.password
	} else {
		var err error
		password, err = o.readPassword()
		if err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return o.decrypt(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := o.decryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}
