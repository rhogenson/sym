package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/subcommands"
	"roseh.moe/pkg/wordlist"
)

type encCmd struct {
	generatePassword bool
	password         string
	force            bool

	passwordIn  func() (string, error)
	passwordOut io.Writer
	stdin       io.Reader
	stdout      io.Writer
}

func (*encCmd) Name() string { return "enc" }
func (*encCmd) Synopsis() string { return "encrypt" }
func (*encCmd) Usage() string {
	return `usage: sym enc [OPTION]... [FILE]...
Encrypt files, or stdin if no files are provided.

One of -g or -p must be used when reading from stdin. When encrypting to
stdout, consider redirecting the result since binary output can mess up
your terminal. Example:
  echo test | sym enc -p 'my super secure password' | base64

`
}

func (c *encCmd) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.generatePassword, "g", false, "generate a secure password automatically (password will be printed to stderr)")
	fs.StringVar(&c.password, "p", "", "use the specified password; if not provided, enc will prompt for a password")
	fs.BoolVar(&c.force, "f", false, "overwrite output files even if they already exist")
}

func (c *encCmd) encrypt(w io.Writer, r io.Reader, password string) error {
	writer := newEncryptingWriter(w, password)
	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	return writer.close()
}

func (c *encCmd) encryptFile(fileName string, password string) (err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	fileOpts := os.O_CREATE | os.O_WRONLY
	if c.force {
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
	if err = c.encrypt(fOut, f, password); err != nil {
		return fmt.Errorf("encrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (c *encCmd) readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter password: ")
	password, err := c.passwordIn()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", usageErr("password cannot be empty")
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	pwConfirm, err := c.passwordIn()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if pwConfirm != password {
		return "", usageErr("passwords do not match")
	}
	return password, nil
}

func (c *encCmd) run(args ...string) error {
	if c.generatePassword && c.password != "" {
		return usageErr("-g and -p cannot be used together")
	}
	if len(args) == 0 && !c.generatePassword && c.password == "" {
		return usageErr("must use -g or -p when reading from stdin")
	}
	var password string
	if c.password != "" {
		password = c.password
	} else if c.generatePassword {
		const nWords = 10
		buf := make([]byte, 2*nWords)
		rand.Read(buf)
		words := make([]string, nWords)
		for i := range words {
			words[i] = wordlist.Words[binary.NativeEndian.Uint16(buf[2*i:])&0x1fff]
		}
		password = strings.Join(words, " ")
		fmt.Fprint(os.Stderr, "Your password: ")
		fmt.Fprint(c.passwordOut, password)
		fmt.Fprintln(os.Stderr)
	} else {
		var err error
		if password, err = c.readPassword(); err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return c.encrypt(c.stdout, c.stdin, password)
	}
	for _, fileName := range args {
		if err := c.encryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}

func (c *encCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.run(f.Args()...); err != nil {
		fmt.Fprintf(os.Stderr, "sym: %s\n", err)
		if errors.Is(err, errUsage) {
			return subcommands.ExitUsageError
		}
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
