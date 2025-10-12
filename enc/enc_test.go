package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"roseh.moe/cmd/sym/internal/sym"
)

func mustWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("Failed to write test file: %s", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file: %s", err)
	}
	return content
}

func TestEnc(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := (&options{password: password}).enc(fileName); err != nil {
		t.Fatalf("enc failed: %s", err)
	}
	if err := sym.DecryptFile(fileName+".enc", password, sym.Force(true)); err != nil {
		t.Fatalf("Failed to decrypt encrypted file: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("encrypt round trip returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestEnc_UsageError(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc             string
		generatePassword bool
		password         string
		files            []string
	}{{
		desc:             "GeneratePasswordAndPassword",
		generatePassword: true,
		password:         "asdf",
	}, {
		desc:             "MissingPasswordStdin",
		generatePassword: false,
		password:         "",
	}, {
		desc:     "NonexistentFile",
		password: "asdf",
		files:    []string{"my-nonexistent-file.txt"},
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			opts := &options{
				generatePassword: tc.generatePassword,
				password:         tc.password,
			}
			if err := opts.enc(tc.files...); err == nil {
				t.Errorf("enc(%+v) succeeded, want error", opts)
			}
		})
	}
}

func TestEnc_GeneratePassword(t *testing.T) {
	t.Parallel()

	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)

	password := new(strings.Builder)
	opts := &options{
		generatePassword: true,
		passwordOut:      password,
	}
	if err := opts.enc(fileName); err != nil {
		t.Fatalf("enc(%+v) failed: %s", opts, err)
	}
	pw := password.String()
	if err := sym.DecryptFile(fileName+".enc", pw, sym.Force(true)); err != nil {
		t.Fatalf("Failed to decrypt encrypted file with generated password %q: %s", pw, err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("encrypt round trip returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestEnc_Stdin(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc  string
		ascii bool
	}{{
		desc:  "Binary",
		ascii: false,
	}, {
		desc:  "ASCII",
		ascii: true,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			const (
				input    = "test input"
				password = "asdf"
			)
			stdout := new(strings.Builder)
			opts := &options{
				password:    password,
				asciiOutput: tc.ascii,
				stdin:       strings.NewReader(input),
				stdout:      stdout,
			}
			if err := opts.enc(); err != nil {
				t.Errorf("enc(+%v) failed: %s", opts, err)
			}
			got := new(strings.Builder)
			if err := sym.Decrypt(got, strings.NewReader(stdout.String()), password); err != nil {
				t.Errorf("Failed to decrypt stdout content: %s", err)
			}
			if got, want := got.String(), input; got != want {
				t.Errorf("Encrypt round-trip to stdout returned incorrect contents: %q, want %q", got, want)
			}
		})
	}
}
