package sym

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
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

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 10*1024*1024)
	for i := range buf {
		buf[i] = byte(i)
	}
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

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, buf)
			const password = "karp cache tidal mars fed rajah uses graze pobox flew"
			if err := EncryptFile(fileName, password, WithASCIIOutput(tc.ascii)); err != nil {
				t.Fatalf("EncryptFile failed: %s", err)
			}
			mustRemove(t, fileName)
			ext := ".enc"
			if tc.ascii {
				ext = ".enc.txt"
			}
			if err := DecryptFile(fileName+ext, password); err != nil {
				t.Fatalf("DecryptFile failed: %s", err)
			}
			gotContents := mustReadFile(t, fileName)
			if !bytes.Equal(gotContents, buf) {
				t.Errorf("contents differ")
			}
		})
	}
}

func TestEncryptFile_Force(t *testing.T) {
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

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, []byte("test file content"))
			mustWriteFile(t, fileName+".enc", []byte("file already exists"))
			err := EncryptFile(fileName, "asdf", Force(tc.force))
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("EncryptFile(force=%t) returned returned error %v when output file exists, want error? %t", tc.force, err, tc.wantErr)
			}
		})
	}
}

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
			if err := EncryptFile(fileName, password); err != nil {
				t.Fatalf("Failed to encrypt file: %s", err)
			}
			err := DecryptFile(fileName+".enc", password, Force(tc.force))
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("DecryptFile(force=%t) returned returned error %v when output file exists, want error? %t", tc.force, err, tc.wantErr)
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
		desc:        "BadHeader",
		fileContent: []byte{0x80, 'a', 's', 'd', 'f'},
	}, {
		desc:        "BadFormat",
		fileContent: []byte("bad file format"),
	}, {
		desc:        "BadContent",
		fileContent: []byte("\x80symasdfasdf"),
	}, {
		desc:        "BadContentLong",
		fileContent: slices.Concat([]byte("\x80sym"), bytes.Repeat([]byte("asdf"), 100)),
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, tc.fileContent)
			err := DecryptFile(fileName, "asdf")
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
	if err := EncryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRename(t, fileName+".enc", fileName+".encrypted")
	if err := DecryptFile(fileName+".encrypted", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName+".encrypted.dec")
	if !bytes.Equal(gotContents, fileContent) {
		t.Errorf("contents differ")
	}
}

func TestEncryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := EncryptFile("my-nonexistent-file.txt", "asdf")
	if err == nil {
		t.Fatal("EncryptFile succeeded for nonexistent file, want error")
	}
}

func TestDecryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := DecryptFile("my-nonexistent-file.txt", "asdf")
	if err == nil {
		t.Fatal("DecryptFile succeeded for nonexistent file, want error")
	}
}
