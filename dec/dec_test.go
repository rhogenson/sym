package main

import (
	"bytes"
	"os"
	"path/filepath"
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

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Failed to remove file: %s", err)
	}
}

func TestDec(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := sym.EncryptFile(fileName, password); err != nil {
		t.Errorf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	err := (&options{password: password}).dec(fileName + ".enc")
	if err != nil {
		t.Errorf("dec failed: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("dec returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestDec_UsageError(t *testing.T) {
	t.Parallel()

	err := (&options{}).dec()
	if err == nil {
		t.Errorf("dec without -p when reading from stdin, want error")
	}
}

func TestDec_NotFound(t *testing.T) {
	t.Parallel()

	err := (&options{password: "asdf"}).dec("my-nonexistent-file-name.txt")
	if err == nil {
		t.Errorf("dec succeeded with nonexistent file, want error")
	}
}

func TestDec_Stdin(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	content := []byte("test contents")
	encrypted := new(bytes.Buffer)
	if err := sym.EncryptBinary(encrypted, bytes.NewReader(content), password); err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}
	gotContentBuf := new(bytes.Buffer)
	opts := &options{
		password: password,
		stdin:    bytes.NewReader(encrypted.Bytes()),
		stdout:   gotContentBuf,
	}
	if err := opts.dec(); err != nil {
		t.Fatalf("dec failed: %s", err)
	}
	gotContent := gotContentBuf.Bytes()
	if !bytes.Equal(gotContent, content) {
		t.Errorf("dec returned incorrect contents %q, want %q", gotContent, content)
	}
}
