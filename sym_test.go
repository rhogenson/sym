package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

var testEncryptOptions = func() encryptOptions {
	opts := defaultEncryptOptions
	opts.iterations = 10
	return opts
}()

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

func mustRename(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.Rename(src, dst); err != nil {
		t.Fatalf("Failed to rename: %s", err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Failed to remove file: %s", err)
	}
}

func mustChmod(t *testing.T, path string, mod os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mod); err != nil {
		t.Fatalf("Failed to chmod: %s", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 12*1024*1024)
	for i := range buf {
		buf[i] = byte(i)
	}

	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, buf)
	const password = "karp cache tidal mars fed rajah uses graze pobox flew"
	if err := testEncryptOptions.encryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	if err := defaultDecryptOptions.decryptFile(fileName+".enc", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotContents, buf) {
		t.Errorf("contents differ")
	}
}
