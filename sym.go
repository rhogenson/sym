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
	switch filepath.Base(name) {
	case "enc":
		return &defaultEncryptOptions, true
	case "dec":
		return &defaultDecryptOptions, true
	default:
		return nil, false
	}
}

func run(args []string) error {
	cmd, ok := whichSubcommand(args[0])
	if !ok {
		if len(args) < 2 {
			return fmt.Errorf("missing subcommand")
		}
		cmd, ok = whichSubcommand(args[1])
		if !ok {
			return fmt.Errorf("invalid subcommand %q", args[1])
		}
		args = args[1:]
	}
	cmd.registerFlags(flag.CommandLine)
	flag.CommandLine.Parse(args[1:])
	return cmd.run(flag.Args()...)
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
