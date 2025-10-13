package sym

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
	"os"

	"golang.org/x/term"
)

const defaultPBKDF2Iters = 35_000_000

//go:generate go tool stringer -type=pwHash -linecomment
type pwHash int8

const (
	pwHashInvalid            pwHash = iota
	pwHashPBKDF2_HMAC_SHA256        // PBKDF2-HMAC-SHA256
)

type hashMetadata struct {
	PasswordHashType pwHash
	Iterations       int32
	SaltSize         int8
}

func (h *hashMetadata) validate() error {
	if h.PasswordHashType != pwHashPBKDF2_HMAC_SHA256 {
		return fmt.Errorf("invalid hash type %q", h.PasswordHashType)
	}
	if h.Iterations <= 0 || h.Iterations > defaultPBKDF2Iters {
		return fmt.Errorf("too many iterations")
	}
	if h.SaltSize <= 0 || h.SaltSize > defaultSaltSize {
		return fmt.Errorf("salt size too long")
	}
	return nil
}

func (h *hashMetadata) hashPassword(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, int(h.Iterations), 32)
}

func termReadPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(pw), nil
}
