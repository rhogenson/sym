package sym

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

func hashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, 35_000_000, 32)
}
