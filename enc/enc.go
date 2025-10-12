package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"roseh.moe/cmd/sym/internal/sym"
	"roseh.moe/pkg/wordlist"
)

type options struct {
	generatePassword bool
	password         string
	asciiOutput      bool
	force            bool

	passwordOut io.Writer
	stdin       io.Reader
	stdout      io.Writer
}

func (o *options) enc(args ...string) error {
	if o.passwordOut == nil {
		o.passwordOut = os.Stderr
	}
	if o.stdin == nil {
		o.stdin = os.Stdin
	}
	if o.stdout == nil {
		o.stdout = os.Stdout
	}
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
		fmt.Fprint(os.Stderr, "Enter password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		password = string(pw)
	}
	if len(args) == 0 {
		if o.asciiOutput {
			return sym.EncryptBase64(o.stdout, o.stdin, password)
		}
		return sym.EncryptBinary(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := sym.EncryptFile(fileName, password, sym.WithASCIIOutput(o.asciiOutput), sym.Force(o.force)); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	o := new(options)
	flag.BoolVar(&o.generatePassword, "g", false, "generate a secure password automatically (password will be printed to stderr)")
	flag.StringVar(&o.password, "p", "", "use the specified password; if not provided, enc will prompt for a password")
	flag.BoolVar(&o.asciiOutput, "a", false, "output in base64, default is binary output")
	flag.BoolVar(&o.force, "f", false, "overwrite output files even if they already exist")
	flag.Parse()
	if err := o.enc(flag.Args()...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
