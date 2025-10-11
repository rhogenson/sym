package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"
	"roseh.moe/cmd/sym/internal/sym"
)

var passwordFlag = flag.String("p", "", "use the specified password; if not provided, dec will prompt for a password")

func dec() error {
	args := flag.Args()
	if len(args) == 0 && *passwordFlag == "" {
		return fmt.Errorf("-p is required when reading from stdin")
	}
	var password string
	if *passwordFlag != "" {
		password = *passwordFlag
	} else {
		fmt.Fprint(os.Stderr, "Enter password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		password = string(pw)
	}
	pwCache := make(sym.PasswordCache)
	if len(args) == 0 {
		return sym.Decrypt(os.Stdout, os.Stdin, password, pwCache)
	}
	for _, fileName := range args {
		if err := sym.DecryptFile(fileName, password, pwCache); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := dec(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
