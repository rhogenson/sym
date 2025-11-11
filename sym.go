// The sym command encrypts or decrypts files with a password.
//
// Sym has two subcommands, enc and dec, which perform encryption and
// decryption. The encryption key is derived from the user's password
// using argon2, and the data is then encrypted using ChaCha20-Poly1305
// in chunks of 1MiB.
//
// Run sym -h for detailed usage information.
//
// # Disclaimer
//
// PLEASE DO NOT USE THIS PROGRAM. It was written for me to learn about
// symmetric encryption, and likely contains critical
// security vulnerabilities.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/subcommands"
)

var errUsage = errors.New("usage error")

type usageError struct {
	msg string
}

func usageErr(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func (e *usageError) Error() string {
	return e.msg
}

func (e *usageError) Is(target error) bool { return target == errUsage }

func registerCommands(commander *subcommands.Commander, passwordIn func() (string, error), passwordOut io.Writer, stdin io.Reader, stdout io.Writer) {
	commander.Register(&encCmd{
		passwordIn:  passwordIn,
		passwordOut: passwordOut,
		stdin:       stdin,
		stdout:      stdout,
	}, "")
	commander.Register(&decCmd{
		passwordIn: passwordIn,
		stdin:      stdin,
		stdout:     stdout,
	}, "")
	commander.Register(commander.HelpCommand(), "")
	commander.Explain = func(w io.Writer) {
		fmt.Fprintf(w, `usage: sym <subcommand> [OPTION]... [FILE]...
Encrypt or decrypt files using a password.

Subcommands:
  enc    encrypt
  dec    decrypt

Try sym <subcommand> -h for command-specific help.
`)
	}
}

func main() {
	ctx := context.Background()
	registerCommands(subcommands.DefaultCommander, termReadPassword, os.Stderr, os.Stdin, os.Stdout)
	flag.Parse()
	os.Exit(int(subcommands.Execute(ctx)))
}
