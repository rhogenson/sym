package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type subcommand interface {
	registerFlags(*flag.FlagSet)
	run(...string) error
}

func whichSubcommand(name string) (subcommand, bool) {
	switch name {
	case "enc":
		return &encryptOptions{
			passwordIn:  termReadPassword,
			passwordOut: os.Stderr,
			stdin:       os.Stdin,
			stdout:      os.Stdout,
		}, true
	case "dec":
		return &decryptOptions{
			passwordIn: termReadPassword,
			stdin:      os.Stdin,
			stdout:     os.Stdout,
		}, true
	default:
		return nil, false
	}
}

func run(args []string) error {
	name := filepath.Base(args[0])
	cmd, ok := whichSubcommand(name)
	if !ok {
		flag.Usage = func() {
			fmt.Fprintf(os.Stderr, `usage: sym <subcommand> [OPTION]... [FILE]...
Encrypt or decrypt files using a password.

Subcommands:
  enc    encrypt
  dec    decrypt

Try sym <subcommand> -h for command-specific help.

Pro tip: use "ln sym enc" or "ln sym dec" to create shortcuts for each subcommand.
`)
		}
		flag.CommandLine.Parse(args[1:])
		args = flag.Args()
		if len(args) == 0 {
			return fmt.Errorf("missing subcommand (use sym -h for help)")
		}
		subcommand := filepath.Base(args[0])
		name = "sym " + subcommand
		cmd, ok = whichSubcommand(subcommand)
		if !ok {
			return fmt.Errorf("invalid subcommand %q", args[0])
		}
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cmd.registerFlags(fs)
	fs.Parse(args[1:])
	return cmd.run(fs.Args()...)
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
