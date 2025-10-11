package sym

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	const password = "karp cache tidal mars fed rajah uses graze pobox flew"
	buf := make([]byte, 10*1024*1024)
	for i := range buf {
		buf[i] = byte(i)
	}
	for _, tc := range []struct {
		desc  string
		ascii bool
	}{{
		desc:  "binary",
		ascii: false,
	}, {
		desc:  "ascii",
		ascii: true,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fileName := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(fileName, buf, 0600); err != nil {
				t.Fatalf("Failed to write test file: %s", err)
			}
			if err := EncryptFile(fileName, password, tc.ascii); err != nil {
				t.Fatalf("EncryptFile failed: %s", err)
			}
			ext := ".enc"
			if tc.ascii {
				ext = ".enc.txt"
			}
			if err := DecryptFile(fileName+ext, password); err != nil {
				t.Fatalf("DecryptFile failed: %s", err)
			}
			gotContents, err := os.ReadFile(fileName)
			if err != nil {
				t.Fatalf("Failed to read file: %s", err)
			}
			if !bytes.Equal(gotContents, buf) {
				t.Errorf("contents differ")
			}
		})
	}
}
