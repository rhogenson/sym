package main

import (
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var argon2Memory = 2 * 1024 * 1024

func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, uint32(argon2Memory), 4, 32)
}

func termReadPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
