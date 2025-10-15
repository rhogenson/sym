package sym

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"roseh.moe/pkg/wordlist"
)

type newlineWriter struct {
	w *bufio.Writer
	n int
}

func (w *newlineWriter) Write(buf []byte) (int, error) {
	const lineSize = 80
	nn := 0
	for len(buf) > 0 {
		if w.n == lineSize {
			if err := w.w.WriteByte('\n'); err != nil {
				return nn, err
			}
			w.n = 0
		}
		n, err := w.w.Write(buf[:min(lineSize-w.n, len(buf))])
		nn += n
		buf = buf[n:]
		w.n += n
		if err != nil {
			return nn, err
		}
	}
	return nn, nil
}

type encryptFlags struct {
	generatePassword bool
	password         string
	asciiOutput      bool
	force            bool
}

func (f *encryptFlags) RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&f.generatePassword, "g", false, "generate a secure password automatically (password will be printed to stderr)")
	fs.StringVar(&f.password, "p", "", "use the specified password; if not provided, enc will prompt for a password")
	fs.BoolVar(&f.asciiOutput, "a", false, "output in base64, default is binary output")
	fs.BoolVar(&f.force, "f", false, "overwrite output files even if they already exist")
}

type EncryptOptions struct {
	encryptFlags

	iterations  int
	passwordIn  func() (string, error)
	passwordOut io.Writer
	stdin       io.Reader
	stdout      io.Writer
}

var DefaultEncryptOptions = EncryptOptions{
	iterations:  defaultPBKDF2Iters,
	passwordIn:  termReadPassword,
	passwordOut: os.Stderr,
	stdin:       os.Stdin,
	stdout:      os.Stdout,
}

func (o *EncryptOptions) encryptBinary(w io.Writer, r io.Reader, password string) error {
	if _, err := io.WriteString(w, magic); err != nil {
		return err
	}
	header := &fileMetadata{
		Version: 0,
		HashMetadata: hashMetadata{
			PasswordHashType: pwHashPBKDF2_HMAC_SHA256,
			Iterations:       int32(o.iterations),
			SaltSize:         defaultSaltSize,
		},
		EncryptionMetadata: encryptionMetadata{
			EncryptionType: encryptionAlgAES256_GCM,
			SegmentSize:    defaultSegmentSize,
		},
	}
	if err := binary.Write(w, binary.BigEndian, header); err != nil {
		return err
	}
	writer := header.EncryptionMetadata.newEncryptingWriter(w, password, &header.HashMetadata)
	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	return writer.Close()
}

func (o *EncryptOptions) encryptBase64(w io.Writer, r io.Reader, password string) error {
	bufWriter := bufio.NewWriter(w)
	if _, err := bufWriter.WriteString(`-------------------------- Begin encrypted text block --------------------------
-------------------------- am i cool like gpg? ---------------------------------
`); err != nil {
		return err
	}
	base64Writer := base64.NewEncoder(base64.StdEncoding, &newlineWriter{w: bufWriter})
	if err := o.encryptBinary(base64Writer, r, password); err != nil {
		return err
	}
	if err := base64Writer.Close(); err != nil {
		return err
	}
	if err := bufWriter.WriteByte('\n'); err != nil {
		return err
	}
	return bufWriter.Flush()
}

func (o *EncryptOptions) encryptFile(fileName string, password string) (err error) {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	ext := ".enc"
	if o.asciiOutput {
		ext = ".enc.txt"
	}
	fileOpts := os.O_CREATE | os.O_WRONLY
	if o.force {
		fileOpts |= os.O_TRUNC
	} else {
		fileOpts |= os.O_EXCL
	}
	fOut, err := os.OpenFile(fileName+ext, fileOpts, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file %q exists (use -f to overwrite)", fileName+ext)
		}
		return err
	}
	defer func() {
		fOut.Close()
		if err != nil {
			os.Remove(fOut.Name())
		}
	}()
	if o.asciiOutput {
		err = o.encryptBase64(fOut, f, password)
	} else {
		err = o.encryptBinary(fOut, f, password)
	}
	if err != nil {
		return fmt.Errorf("encrypt %q: %s", fileName, err)
	}
	return fOut.Close()
}

func (o *EncryptOptions) readPassword() (string, error) {
	const maxAttempts = 3
	for i := 1; i <= maxAttempts; i++ {
		fmt.Fprint(os.Stderr, "Enter password")
		if i > 1 {
			fmt.Fprintf(os.Stderr, " (attempt %d/%d)", i, maxAttempts)
		}
		fmt.Fprint(os.Stderr, ": ")
		password, err := o.passwordIn()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if password == "" {
			fmt.Fprintln(os.Stderr, "Password cannot be empty")
			continue
		}
		fmt.Fprint(os.Stderr, "Repeat password: ")
		pwConfirm, err := o.passwordIn()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if pwConfirm != password {
			fmt.Fprintln(os.Stderr, "Passwords do not match")
			continue
		}
		return password, nil
	}
	return "", fmt.Errorf("too many attempts")
}

func (o *EncryptOptions) Run(args ...string) error {
	if o.generatePassword && o.password != "" {
		return fmt.Errorf("-g and -p cannot be used together")
	}
	if len(args) == 0 && !o.generatePassword && o.password == "" {
		return fmt.Errorf("must use -g or -p when reading from stdin")
	}
	var password string
	if o.password != "" {
		password = o.password
	} else if o.generatePassword {
		const nWords = 10
		buf := make([]byte, 2*nWords)
		rand.Read(buf)
		words := make([]string, nWords)
		for i := range words {
			words[i] = wordlist.Words[binary.NativeEndian.Uint16(buf[2*i:])&0x1fff]
		}
		password = strings.Join(words, " ")
		fmt.Fprint(os.Stderr, "Your password: ")
		fmt.Fprint(o.passwordOut, password)
		fmt.Fprintln(os.Stderr)
	} else {
		var err error
		if password, err = o.readPassword(); err != nil {
			return err
		}
	}
	if len(args) == 0 {
		if o.asciiOutput {
			return o.encryptBase64(o.stdout, o.stdin, password)
		}
		return o.encryptBinary(o.stdout, o.stdin, password)
	}
	for _, fileName := range args {
		if err := o.encryptFile(fileName, password); err != nil {
			return err
		}
	}
	return nil
}
