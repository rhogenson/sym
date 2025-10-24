package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

var testEncryptionMetadata = encryptionMetadata{
	EncryptionType: encryptionAlgAES256_GCM,
	SegmentSize:    18,
}

var testHashMetadata = hashMetadata{
	PasswordHashType: pwHashPBKDF2_HMAC_SHA256,
	Iterations:       10,
	SaltSize:         defaultSaltSize,
}

func TestOAEReadWrite(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	input := strings.Repeat("test input", 1024)
	out := new(bytes.Buffer)
	writer := testEncryptionMetadata.newEncryptingWriter(out, password, &testHashMetadata)
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatalf("Failed to write: %s", err)
	}
	if err := writer.close(); err != nil {
		t.Fatalf("writer.Close() failed: %s", err)
	}
	got, err := io.ReadAll(testEncryptionMetadata.newDecryptingReader(bytes.NewReader(out.Bytes()), password, &testHashMetadata))
	if err != nil {
		t.Fatalf("Failed to decrypt: %s", err)
	}
	if string(got) != input {
		t.Errorf("Input failed to round-trip")
	}
}
