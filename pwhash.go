package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"os"

	"golang.org/x/term"
)

const defaultPBKDF2Iters = 35_000_000

func hashPassword(password string, salt []byte, iters int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iters, 32)
}

func termReadPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
