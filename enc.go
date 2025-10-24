package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"roseh.moe/pkg/wordlist"
)

type encryptFlags struct {
	generatePassword bool
	password         string
	force            bool
}

func (f *encryptFlags) registerFlags(fs *flag.FlagSet) {
	fs.BoolVar(&f.generatePassword, "g", false, "generate a secure password automatically (password will be printed to stderr)")
	fs.StringVar(&f.password, "p", "", "use the specified password; if not provided, enc will prompt for a password")
	fs.BoolVar(&f.force, "f", false, "overwrite output files even if they already exist")
}

type encryptOptions struct {
	encryptFlags

	memory      int
	passwordIn  func() (string, error)
	passwordOut io.Writer
	stdin       io.Reader
	stdout      io.Writer
}

var defaultEncryptOptions = encryptOptions{
	memory:      defaultArgon2Memory,
	passwordIn:  termReadPassword,
	passwordOut: os.Stderr,
	stdin:       os.Stdin,
	stdout:      os.Stdout,
}

func (o *encryptOptions) encrypt(w io.Writer, r io.Reader, password string) error {
	writer := newEncryptingWriter(w, password, o.memory)
	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	return writer.close()
}

func (o *encryptOptions) encryptFile(fileName string, password string) (err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	fileOpts := os.O_CREATE | os.O_WRONLY
	if o.force {
		fileOpts |= os.O_TRUNC
	} else {
		fileOpts |= os.O_EXCL
	}
	fOut, err := os.OpenFile(fileName+".enc", fileOpts, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file %q exists (use -f to overwrite)", fileName+".enc")
		}
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if err = o.encrypt(fOut, f, password); err != nil {
		return fmt.Errorf("encrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (o *encryptOptions) readPassword() (string, error) {
	const maxAttempts = 3
	for i := 1; i <= maxAttempts; i++ {
		fmt.Fprint(os.Stderr, "Enter password")
		if i > 1 {
			fmt.Fprintf(os.Stderr, " (attempt %d/%d)", i, maxAttempts)
		}
		fmt.Fprint(os.Stderr, ": ")
		password, err := o.passwordIn()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if password == "" {
			fmt.Fprintln(os.Stderr, "Password cannot be empty")
			continue
		}
		fmt.Fprint(os.Stderr, "Repeat password: ")
		pwConfirm, err := o.passwordIn()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if pwConfirm != password {
			fmt.Fprintln(os.Stderr, "Passwords do not match")
			continue
		}
		return password, nil
	}
	return "", fmt.Errorf("too many attempts")
}

func (o *encryptOptions) run(args ...string) error {
	if o.generatePassword && o.password != "" {
		return fmt.Errorf("-g and -p cannot be used together")
	}
	if len(args) == 0 && !o.generatePassword && o.password == "" {
		return fmt.Errorf("must use -g or -p when reading from stdin")
	}
	var password string
	if o.password != "" {
		password = o.password
	} else if o.generatePassword {
		const nWords = 10
		buf := make([]byte, 2*nWords)
		rand.Read(buf)
		words := make([]string, nWords)
		for i := range words {
			words[i] = wordlist.Words[binary.NativeEndian.Uint16(buf[2*i:])&0x1fff]
		}
		password = strings.Join(words, " ")
		fmt.Fprint(os.Stderr, "Your password: ")
		fmt.Fprint(o.passwordOut, password)
		fmt.Fprintln(os.Stderr)
	} else {
		var err error
		if password, err = o.readPassword(); err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return o.encrypt(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := o.encryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}
