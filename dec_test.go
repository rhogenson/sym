package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDecryptFile_Force(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc    string
		force   bool
		wantErr bool
	}{{
		desc:    "OutputExists",
		force:   false,
		wantErr: true,
	}, {
		desc:    "Force",
		force:   true,
		wantErr: false,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			const password = "asdf"
			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, []byte("test file content"))
			if err := (&encCmd{}).encryptFile(fileName, password); err != nil {
				t.Fatalf("Failed to encrypt file: %s", err)
			}
			err := (&decCmd{force: tc.force}).decryptFile(fileName+".enc", password)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("decryptFile(force=%t) returned returned error %v when output file exists, want error? %t", tc.force, err, tc.wantErr)
			}
		})
	}
}

func TestDecrypt_BadFileFormat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc        string
		fileContent []byte
	}{{
		desc:        "Empty",
		fileContent: nil,
	}, {
		desc:        "Short",
		fileContent: []byte{0x80},
	}, {
		desc:        "NoContent",
		fileContent: bytes.Repeat([]byte{0}, saltSize),
	}, {
		desc: "BadContent",
		fileContent: slices.Concat(
			bytes.Repeat([]byte{0}, saltSize),
			[]byte("bad content")),
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, tc.fileContent)
			err := (&decCmd{}).decryptFile(fileName, "asdf")
			if err == nil {
				t.Errorf("DecryptFile succeeded for incorrect file format, want error")
			}
		})
	}
}

func TestDecryptFile_WeirdName(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := (&encCmd{}).encryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRename(t, fileName+".enc", fileName+".encrypted")
	if err := (&decCmd{}).decryptFile(fileName+".encrypted", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName+".encrypted.dec")
	if !bytes.Equal(gotContents, fileContent) {
		t.Errorf("contents differ")
	}
}

func TestDecryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := (&decCmd{}).decryptFile("my-nonexistent-file.txt", "asdf")
	if err == nil {
		t.Fatal("decryptFile succeeded for nonexistent file, want error")
	}
}

func TestDecryptFile_NoPermission(t *testing.T) {
	t.Parallel()

	fileName := filepath.Join(t.TempDir(), "file.enc")
	mustWriteFile(t, fileName, []byte("test file content"))
	mustWriteFile(t, strings.TrimSuffix(fileName, ".enc"), nil)
	mustChmod(t, strings.TrimSuffix(fileName, ".enc"), 0400)
	err := (&decCmd{force: true}).decryptFile(fileName, "asdf")
	if err == nil {
		t.Fatal("decryptFile succeeded for unwritable file, want error")
	}
}

func TestDecCmd_Run(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := (&encCmd{}).encryptFile(fileName, password); err != nil {
		t.Errorf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	err := (&decCmd{password: password}).run(fileName + ".enc")
	if err != nil {
		t.Errorf("decCmd.run failed: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("run returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestDecCmd_Run_UsageError(t *testing.T) {
	t.Parallel()

	err := (&decCmd{}).run()
	if err == nil {
		t.Errorf("Run without -p when reading from stdin, want error")
	}
}

func TestDecCmd_Run_NotFound(t *testing.T) {
	t.Parallel()

	err := (&decCmd{password: "asdf"}).run("my-nonexistent-file-name.txt")
	if err == nil {
		t.Errorf("run succeeded with nonexistent file, want error")
	}
}

func TestDecCmd_Run_Stdin(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	content := []byte("test contents")
	encrypted := new(bytes.Buffer)
	if err := (&encCmd{}).encrypt(encrypted, bytes.NewReader(content), password); err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}
	gotContentBuf := new(bytes.Buffer)
	if err := (&decCmd{
		password: password,
		stdin:    bytes.NewReader(encrypted.Bytes()),
		stdout:   gotContentBuf,
	}).run(); err != nil {
		t.Fatalf("run failed: %s", err)
	}
	gotContent := gotContentBuf.Bytes()
	if !bytes.Equal(gotContent, content) {
		t.Errorf("dec returned incorrect contents %q, want %q", gotContent, content)
	}
}

func TestDecCmd_Run_ReadPassword(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc    string
		err     error
		wantErr bool
	}{{
		desc: "Ok",
	}, {
		desc:    "Err",
		err:     errors.New("test error"),
		wantErr: true,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			const password = "asdf"

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, []byte("test file content"))
			if err := (&encCmd{}).encryptFile(fileName, password); err != nil {
				t.Errorf("EncryptFile failed: %s", err)
			}
			mustRemove(t, fileName)

			err := (&decCmd{
				passwordIn: func() (string, error) {
					return password, tc.err
				},
			}).run(fileName + ".enc")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("decCmd.run returned error %v reading password from stdin, want error? %t", err, tc.wantErr)
			}
		})
	}
}
