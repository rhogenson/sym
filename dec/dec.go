package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
	"roseh.moe/cmd/sym/internal/sym"
)

type options struct {
	password string
	force    bool

	stdin  io.Reader
	stdout io.Writer
}

func (o *options) dec(args ...string) error {
	if o.stdin == nil {
		o.stdin = os.Stdin
	}
	if o.stdout == nil {
		o.stdout = os.Stdout
	}
	if len(args) == 0 && o.password == "" {
		return fmt.Errorf("-p is required when reading from stdin")
	}
	var password string
	if o.password != "" {
		password = o.password
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
		return sym.Decrypt(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := sym.DecryptFile(fileName, password, sym.Force(o.force)); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	o := new(options)
	flag.StringVar(&o.password, "p", "", "use the specified password; if not provided, dec will prompt for a password")
	flag.BoolVar(&o.force, "f", false, "overwrite output files even if they already exist")
	flag.Parse()
	if err := o.dec(flag.Args()...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
