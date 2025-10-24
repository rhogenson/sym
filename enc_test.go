package main

import (
	"bytes"
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"testing"
)

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
			encOpts := testEncryptOptions
			encOpts.force = tc.force
			err := encOpts.encryptFile(fileName, "asdf")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("EncryptFile(force=%t) returned returned error %v when output file exists, want error? %t", tc.force, err, tc.wantErr)
			}
		})
	}
}

func TestEncryptFile_NotFound(t *testing.T) {
	t.Parallel()

	err := testEncryptOptions.encryptFile("my-nonexistent-file.txt", "asdf")
	if err == nil {
		t.Fatal("encryptFile succeeded for nonexistent file, want error")
	}
}

func TestEncryptFile_NoPermission(t *testing.T) {
	t.Parallel()

	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, []byte("test file content"))
	mustWriteFile(t, fileName+".enc", nil)
	mustChmod(t, fileName+".enc", 0400)
	opts := testEncryptOptions
	opts.force = true
	err := opts.encryptFile(fileName, "asdf")
	if err == nil {
		t.Fatal("encryptFile succeeded for unwritable file, want error")
	}
}

func TestEncryptOptions_RegisterFlags(t *testing.T) {
	t.Parallel()

	var o encryptOptions
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.registerFlags(fs)
	const cmd = "-g -p asdf -f"
	fs.Parse(strings.Split(cmd, " "))
	want := encryptFlags{
		generatePassword: true,
		password:         "asdf",
		force:            true,
	}
	if o.encryptFlags != want {
		t.Errorf("Command line %q parsed incorrect encryptOptions, got %+v, want %+v", cmd, o, want)
	}
}

func TestEncryptOptions_Run(t *testing.T) {
	t.Parallel()

	const password = "asdf"
	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)
	opts := testEncryptOptions
	opts.password = password
	if err := opts.run(fileName); err != nil {
		t.Fatalf("enc failed: %s", err)
	}
	mustRemove(t, fileName)
	if err := testDecryptOptions.decryptFile(fileName+".enc", password); err != nil {
		t.Fatalf("Failed to decrypt encrypted file: %s", err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("encrypt round trip returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestEncryptOptions_Run_UsageError(t *testing.T) {
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

			opts := testEncryptOptions
			opts.generatePassword = tc.generatePassword
			opts.password = tc.password
			if err := opts.run(tc.files...); err == nil {
				t.Errorf("run(%+v) succeeded, want error", opts)
			}
		})
	}
}

func TestEncryptOptions_Run_GeneratePassword(t *testing.T) {
	t.Parallel()

	fileContent := []byte("test file content")
	fileName := filepath.Join(t.TempDir(), "file")
	mustWriteFile(t, fileName, fileContent)

	password := new(strings.Builder)
	opts := testEncryptOptions
	opts.generatePassword = true
	opts.passwordOut = password
	if err := opts.run(fileName); err != nil {
		t.Fatalf("enc(%+v) failed: %s", opts, err)
	}
	pw := password.String()
	mustRemove(t, fileName)
	if err := testDecryptOptions.decryptFile(fileName+".enc", pw); err != nil {
		t.Fatalf("Failed to decrypt encrypted file with generated password %q: %s", pw, err)
	}
	gotFileContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotFileContents, fileContent) {
		t.Errorf("encrypt round trip returned incorrect contents %q, want %q", gotFileContents, fileContent)
	}
}

func TestEncryptOptions_Run_Stdin(t *testing.T) {
	t.Parallel()

	const (
		input    = "test input"
		password = "asdf"
	)
	stdout := new(strings.Builder)
	opts := testEncryptOptions
	opts.password = password
	opts.stdin = strings.NewReader(input)
	opts.stdout = stdout
	if err := opts.run(); err != nil {
		t.Errorf("enc(+%v) failed: %s", opts, err)
	}
	got := new(strings.Builder)
	if err := testDecryptOptions.decrypt(got, strings.NewReader(stdout.String()), password); err != nil {
		t.Errorf("Failed to decrypt stdout content %q: %s", stdout, err)
	}
	if got, want := got.String(), input; got != want {
		t.Errorf("Encrypt round-trip to stdout returned incorrect contents: %q, want %q", got, want)
	}
}

func TestEncryptOptions_Run_ReadPassword(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc      string
		passwords []string
		err       error
		wantErr   bool
	}{{
		desc:      "Ok",
		passwords: []string{"asdf"},
	}, {
		desc:      "EmptyPassword",
		passwords: []string{""},
		wantErr:   true,
	}, {
		desc:      "PasswordsDoNotMatch",
		passwords: []string{"asdf", "jkl"},
		wantErr:   true,
	}, {
		desc:    "ReadPasswordErr",
		err:     errors.New("test error"),
		wantErr: true,
	}, {
		desc:      "RepeatPasswordErr",
		passwords: []string{"asdf"},
		err:       errors.New("test error"),
		wantErr:   true,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			fileName := filepath.Join(t.TempDir(), "file")
			mustWriteFile(t, fileName, []byte("test file content"))

			opts := testEncryptOptions
			passwordI := 0
			opts.passwordIn = func() (string, error) {
				if passwordI == len(tc.passwords) && tc.err != nil {
					return "", tc.err
				}
				pw := tc.passwords[passwordI%len(tc.passwords)]
				passwordI++
				return pw, nil
			}
			err := opts.run(fileName)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("encryptOptions.run returned error %v, want error? %t", err, tc.wantErr)
			}
		})
	}
}
