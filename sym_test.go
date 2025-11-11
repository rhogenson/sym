package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/subcommands"
)

func init() {
	argon2Memory = 1
}

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
	if err := (&encCmd{}).encryptFile(fileName, password); err != nil {
		t.Fatalf("EncryptFile failed: %s", err)
	}
	mustRemove(t, fileName)
	if err := (&decCmd{}).decryptFile(fileName+".enc", password); err != nil {
		t.Fatalf("DecryptFile failed: %s", err)
	}
	gotContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotContents, buf) {
		t.Errorf("contents differ")
	}
}

func run(ctx context.Context, t *testing.T, cmd ...string) subcommands.ExitStatus {
	t.Helper()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	commander := subcommands.NewCommander(fs, "test")
	registerCommands(commander, nil, nil, nil, nil)
	if err := fs.Parse(cmd); err != nil {
		t.Fatalf("Failed to parse command %q: %s", cmd, err)
	}
	return commander.Execute(ctx)
}

func TestCommander(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	fileName := filepath.Join(t.TempDir(), "file.txt")
	const fileContent = "test file content"
	mustWriteFile(t, fileName, []byte(fileContent))
	const password = "asdf"
	if st := run(ctx, t, "enc", "-p="+password, fileName); st != subcommands.ExitSuccess {
		t.Fatalf("enc failed: status %d", st)
	}
	mustRemove(t, fileName)
	if st := run(ctx, t, "dec", "-p="+password, fileName+".enc"); st != subcommands.ExitSuccess {
		t.Fatalf("dec failed: status %d", st)
	}
	gotContents := mustReadFile(t, fileName)
	if !bytes.Equal(gotContents, []byte(fileContent)) {
		t.Errorf("dec returned invalid content, got %q, want %q", gotContents, fileContent)
	}
}

func TestCommander_Errors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		desc string
		cmd []string
		wantStatus subcommands.ExitStatus
	} {{
		desc: "EncUsageError",
		cmd: []string{"enc", "-g", "-p=asdf", "file.txt"},
		wantStatus: subcommands.ExitUsageError,
	}, {
		desc: "EncNoSuchFile",
		cmd: []string{"enc", "-p=asdf", "nonexistent-file.txt"},
		wantStatus: subcommands.ExitFailure,
	}, {
		desc: "DecUsageError",
		cmd: []string{"dec"},
		wantStatus: subcommands.ExitUsageError,
	}, {
		desc: "DecNoSuchFile",
		cmd: []string{"dec", "-p=asdf", "nonexistent-file.txt.enc"},
		wantStatus: subcommands.ExitFailure,
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			st := run(ctx, t, tc.cmd...)
			if st != tc.wantStatus {
				t.Errorf("command %q returned status %d, want %d", tc.cmd, st, tc.wantStatus)
			}
		})
	}
}

func TestUsage(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	run(ctx, t, "help")
	run(ctx, t, "enc", "-h")
	run(ctx, t, "dec", "-h")
}
