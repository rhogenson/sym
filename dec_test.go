package sym

import (
	"bytes"
	"encoding/binary"
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
			if err := testEncryptOptions.encryptFile(fileName, password); err != nil {
				t.Fatalf("Failed to encrypt file: %s", err)
			}
			decOpts := DefaultDecryptOptions
			decOpts.force = tc.force
			err := decOpts.decryptFile(fileName+".enc", password)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("decryptFile(force=%t) returned returned error %v when output file exists, want error? %t", tc.force, err, tc.wantErr)
			}
		})
	}
}

func encodeHeader(t *testing.T, f *fileMetadata) []byte {
	t.Helper()

	if f.HashMetadata.PasswordHashType == pwHashInvalid {
		f.HashMetadata.PasswordHashType = pwHashPBKDF2_HMAC_SHA256
	}
	if f.HashMetadata.Iterations == 0 {
		f.HashMetadata.Iterations = 10
	}
	if f.HashMetadata.SaltSize == 0 {
		f.HashMetadata.SaltSize = defaultSaltSize
	}
	if f.EncryptionMetadata.EncryptionType == encryptionAlgInvalid {
		f.EncryptionMetadata.EncryptionType = encryptionAlgAES256_GCM
	}
	if f.EncryptionMetadata.SegmentSize == 0 {
		f.EncryptionMetadata.SegmentSize = defaultSegmentSize
	}
	b, err := binary.Append([]byte(magic), binary.BigEndian, f)
	if err != nil {
		t.Fatalf("Bad file metadata: %s", err)
	}
	return b
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
		desc:        "BadFormat",
		fileContent: []byte("bad file format"),
	}, {
		desc:        "BadMagic",
		fileContent: []byte("\x80asdf"),
	}, {
		desc:        "BadHeader",
		fileContent: []byte("\x80symasdf"),
	}, {
		desc: "BadVersion",
		fileContent: encodeHeader(t, &fileMetadata{
			Version: -1,
		}),
	}, {
		desc: "BadEncryptionAlg",
		fileContent: encodeHeader(t, &fileMetadata{
			EncryptionMetadata: encryptionMetadata{
				EncryptionType: -1,
			},
		}),
	}, {
		desc: "BadSegmentSize",
		fileContent: encodeHeader(t, &fileMetadata{
			EncryptionMetadata: encryptionMetadata{
				SegmentSize: -1,
			},
		}),
	}, {
		desc: "BadSaltSize",
		fileContent: encodeHeader(t, &fileMetadata{
			HashMetadata: hashMetadata{
				SaltSize: -1,
			},
		}),
	}, {
		desc: "BadPasswordHashType",
		fileContent: encodeHeader(t, &fileMetadata{
			HashMetadata: hashMetadata{
				PasswordHashType: -1,
			},
		}),
	}, {
		desc: "BadIterations",
		fileContent: encodeHeader(t, &fileMetadata{
			HashMetadata: hashMetadata{
				Iterations: -1,
			},
		}),
	}, {
		desc:        "NoSalt",
		fileContent: encodeHeader(t, &fileMetadata{}),
	}, {
		desc: "ShortSalt",
		fileContent: slices.Concat(
			encodeHeader(t, &fileMetadata{}),
			[]byte("asdf")),
	}, {
		desc: "BadContent",
		fileContent: slices.Concat(
			encodeHeader(t, &fileMetadata{}),
			bytes.Repeat([]byte{0}, defaultSaltSize),
			[]byte("bad content")),
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, tc.fileContent)
			err := DefaultDecryptOptions.decryptFile(fileName, "asdf")
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
	if err := testEncryptOptions.encryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRename(t, fileName+".enc", fileName+".encrypted")
	if err := DefaultDecryptOptions.decryptFile(fileName+".encrypted", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName+".encrypted.dec")
	if !bytes.Equal(gotContents, fileContent) {
		t.Errorf("contents differ")
	}
}

func TestDecryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := DefaultDecryptOptions.decryptFile("my-nonexistent-file.txt", "asdf")
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
	opts := DefaultDecryptOptions
	opts.force = true
	err := opts.decryptFile(fileName, "asdf")
	if err == nil {
		t.Fatal("decryptFile succeeded for unwritable file, want error")
	}
}

func TestDecryptOptions_RegisterFlags(t *testing.T) {
	t.Parallel()

	var o DecryptOptions
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.RegisterFlags(fs)
	const cmd = "-p asdf -f"
	fs.Parse(strings.Split(cmd, " "))
	want := decryptFlags{
		password: "asdf",
		force:    true,
	}
	if o.decryptFlags != want {
		t.Errorf("Command line %q parsed incorrect DecryptOptions, got %+v, want %+v", cmd, o, want)
	}
}

func TestDecryptOptions_Run(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	if err := testEncryptOptions.encryptFile(fileName, password); err != nil {
		t.Errorf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	opts := DefaultDecryptOptions
	opts.password = password
	err := opts.Run(fileName + ".enc")
	if err != nil {
		t.Errorf("dec failed: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("Run returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestDecryptOptions_Run_UsageError(t *testing.T) {
	t.Parallel()

	err := DefaultDecryptOptions.Run()
	if err == nil {
		t.Errorf("Run without -p when reading from stdin, want error")
	}
}

func TestDecryptOptions_Run_NotFound(t *testing.T) {
	t.Parallel()

	opts := DefaultDecryptOptions
	opts.password = "asdf"
	err := opts.Run("my-nonexistent-file-name.txt")
	if err == nil {
		t.Errorf("Run succeeded with nonexistent file, want error")
	}
}

func TestDecryptOptions_Run_Stdin(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	content := []byte("test contents")
	encrypted := new(bytes.Buffer)
	if err := testEncryptOptions.encrypt(encrypted, bytes.NewReader(content), password); err != nil {
		t.Fatalf("Failed to encrypt: %s", err)
	}
	gotContentBuf := new(bytes.Buffer)
	opts := DefaultDecryptOptions
	opts.password = password
	opts.stdin = bytes.NewReader(encrypted.Bytes())
	opts.stdout = gotContentBuf
	if err := opts.Run(); err != nil {
		t.Fatalf("Run failed: %s", err)
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
			if err := testEncryptOptions.encryptFile(fileName, password); err != nil {
				t.Errorf("EncryptFile failed: %s", err)
			}
			mustRemove(t, fileName)

			opts := DefaultDecryptOptions
			opts.passwordIn = func() (string, error) {
				return password, tc.err
			}
			err := opts.Run(fileName + ".enc")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("DecryptOptions.Run returned error %v reading password from stdin, want error? %t", err, tc.wantErr)
			}
		})
	}
}
