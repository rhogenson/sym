package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/subcommands"
)

type decCmd struct {
	password string
	force    bool

	passwordIn func() (string, error)
	stdin      io.Reader
	stdout     io.Writer
}

func (*decCmd) Name() string     { return "dec" }
func (*decCmd) Synopsis() string { return "decrypt" }
func (*decCmd) Usage() string {
	return `usage: sym dec [OPTION]... [FILE]...
Decrypt files, or stdin if no files are provided.

-p is required when reading from stdin.

For example,
  sym dec my-encrypted-file.txt.enc
would decrypt my-encrypted-file.txt.enc and write the result to
my-encrypted-file.txt. If a filename does not end with .enc, the name
will be appended with a .dec extension.

`
}

func (c *decCmd) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.password, "p", "", "use the specified password; if not provided, dec will prompt for a password")
	fs.BoolVar(&c.force, "f", false, "overwrite output files even if they already exist")
}

func (c *decCmd) decrypt(w io.Writer, r io.Reader, password string) error {
	_, err := io.Copy(w, newDecryptingReader(r, password))
	return err
}

func (c *decCmd) decryptFile(fileName string, password string) (err error) {
	var outFileName string
	if name, ok := strings.CutSuffix(fileName, ".enc"); ok {
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
	if c.force {
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
	if err := c.decrypt(fOut, fIn, password); err != nil {
		return fmt.Errorf("decrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (c *decCmd) readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter password: ")
	pw, err := c.passwordIn()
	fmt.Fprintln(os.Stderr)
	return pw, err
}

func (c *decCmd) run(args ...string) error {
	if len(args) == 0 && c.password == "" {
		return usageErr("-p is required when reading from stdin")
	}
	var password string
	if c.password != "" {
		password = c.password
	} else {
		var err error
		password, err = c.readPassword()
		if err != nil {
			return err
		}
	}
	if len(args) == 0 {
		return c.decrypt(c.stdout, c.stdin, password)
	}
	for _, fileName := range args {
		if err := c.decryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}

func (c *decCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.run(f.Args()...); err != nil {
		fmt.Fprintf(os.Stderr, "sym: %s\n", err)
		if errors.Is(err, errUsage) {
			return subcommands.ExitUsageError
		}
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
