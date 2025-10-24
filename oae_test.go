package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestOAEReadWrite(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	input := strings.Repeat("test input", 1024)
	out := new(bytes.Buffer)
	writer := newEncryptingWriter(out, password)
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatalf("Failed to write: %s", err)
	}
	if err := writer.close(); err != nil {
		t.Fatalf("writer.Close() failed: %s", err)
	}
	got, err := io.ReadAll(newDecryptingReader(bytes.NewReader(out.Bytes()), password))
	if err != nil {
		t.Fatalf("Failed to decrypt: %s", err)
	}
	if string(got) != input {
		t.Errorf("Input failed to round-trip")
	}
}
