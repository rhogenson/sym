package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
	"roseh.moe/cmd/sym/internal/sym"
	"roseh.moe/pkg/wordlist"
)

var (
	generatePassword = flag.Bool("g", false, "generate a secure password automatically (password will be printed to stderr)")
	passwordFlag     = flag.String("p", "", "use the specified password; if not provided, enc will prompt for a password")
	asciiOutput      = flag.Bool("a", false, "Output in base64, default is binary output")
)

func enc() error {
	if *generatePassword && *passwordFlag != "" {
		return fmt.Errorf("-g and -p cannot be used together")
	}
	args := flag.Args()
	if len(args) == 0 && !*generatePassword && *passwordFlag == "" {
		return fmt.Errorf("must use -g or -p when reading from stdin")
	}
	var password string
	if *passwordFlag != "" {
		password = *passwordFlag
	} else if *generatePassword {
		const nWords = 10
		buf := make([]byte, 2*nWords)
		rand.Read(buf)
		words := make([]string, nWords)
		for i := range words {
			words[i] = wordlist.Words[binary.NativeEndian.Uint16(buf[2*i:])&0x1fff]
		}
		password = strings.Join(words, " ")
		fmt.Fprintf(os.Stderr, "Your password: %s\n", password)
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
		if *asciiOutput {
			return sym.EncryptBase64(os.Stdout, os.Stdin, password)
		}
		return sym.EncryptBinary(os.Stdout, os.Stdin, password)
	}
	for _, fileName := range args {
		if err := sym.EncryptFile(fileName, password, *asciiOutput); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := enc(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
