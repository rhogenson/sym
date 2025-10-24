package main

import (
	"bytes"
	"errors"
	"flag"
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
			if err := (&encryptOptions{}).encryptFile(fileName, password); err != nil {
				t.Fatalf("Failed to encrypt file: %s", err)
			}
			err := (&decryptOptions{decryptFlags: decryptFlags{force: tc.force}}).decryptFile(fileName+".enc", password)
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
			err := (&decryptOptions{}).decryptFile(fileName, "asdf")
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
	if err := (&encryptOptions{}).encryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRename(t, fileName+".enc", fileName+".encrypted")
	if err := (&decryptOptions{}).decryptFile(fileName+".encrypted", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName+".encrypted.dec")
	if !bytes.Equal(gotContents, fileContent) {
		t.Errorf("contents differ")
	}
}

func TestDecryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := (&decryptOptions{}).decryptFile("my-nonexistent-file.txt", "asdf")
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
	err := (&decryptOptions{decryptFlags: decryptFlags{force: true}}).decryptFile(fileName, "asdf")
	if err == nil {
		t.Fatal("decryptFile succeeded for unwritable file, want error")
	}
}

func TestDecryptOptions_RegisterFlags(t *testing.T) {
	t.Parallel()

	var o decryptOptions
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.registerFlags(fs)
	const cmd = "-p asdf -f"
	fs.Parse(strings.Split(cmd, " "))
	want := decryptFlags{
		password: "asdf",
		force:    true,
	}
	if o.decryptFlags != want {
		t.Errorf("Command line %q parsed incorrect decryptOptions, got %+v, want %+v", cmd, o, want)
	}
}

func TestDecryptOptions_Run(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := (&encryptOptions{}).encryptFile(fileName, password); err != nil {
		t.Errorf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	err := (&decryptOptions{decryptFlags: decryptFlags{password: password}}).run(fileName + ".enc")
	if err != nil {
		t.Errorf("decryptOptions.run failed: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("run returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestDecryptOptions_Run_UsageError(t *testing.T) {
	t.Parallel()

	err := (&decryptOptions{}).run()
	if err == nil {
		t.Errorf("Run without -p when reading from stdin, want error")
	}
}

func TestDecryptOptions_Run_NotFound(t *testing.T) {
	t.Parallel()

	err := (&decryptOptions{decryptFlags: decryptFlags{password: "asdf"}}).run("my-nonexistent-file-name.txt")
	if err == nil {
		t.Errorf("run succeeded with nonexistent file, want error")
	}
}

func TestDecryptOptions_Run_Stdin(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	content := []byte("test contents")
	encrypted := new(bytes.Buffer)
	if err := (&encryptOptions{}).encrypt(encrypted, bytes.NewReader(content), password); err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}
	gotContentBuf := new(bytes.Buffer)
	if err := (&decryptOptions{
		decryptFlags: decryptFlags{password: password},
		stdin:        bytes.NewReader(encrypted.Bytes()),
		stdout:       gotContentBuf,
	}).run(); err != nil {
		t.Fatalf("run failed: %s", err)
	}
	gotContent := gotContentBuf.Bytes()
	if !bytes.Equal(gotContent, content) {
		t.Errorf("dec returned incorrect contents %q, want %q", gotContent, content)
	}
}

func TestDecryptOptions_Run_ReadPassword(t *testing.T) {
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
			if err := (&encryptOptions{}).encryptFile(fileName, password); err != nil {
				t.Errorf("EncryptFile failed: %s", err)
			}
			mustRemove(t, fileName)

			err := (&decryptOptions{
				passwordIn: func() (string, error) {
					return password, tc.err
				},
			}).run(fileName + ".enc")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("decryptOptions.run returned error %v reading password from stdin, want error? %t", err, tc.wantErr)
			}
		})
	}
}
