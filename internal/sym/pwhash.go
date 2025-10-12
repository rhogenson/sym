package sym

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"os"

	"golang.org/x/term"
)

func hashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, 35_000_000, 32)
}

func termReadPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
