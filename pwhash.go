package main

import (
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const defaultArgon2Memory = 64 * 1024

func hashPassword(password string, salt []byte, memory int) ([]byte, error) {
	return argon2.IDKey([]byte(password), salt, 1, uint32(memory), 4, 32), nil
}

func termReadPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
