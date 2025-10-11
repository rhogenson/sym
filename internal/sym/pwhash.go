package sym

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

const SaltSize = 16

func HashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, 35_000_000, 32)
}
