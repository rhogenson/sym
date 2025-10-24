package main

import "fmt"

const magic = "\x80sym"

type fileMetadata struct {
	Version            int8
	HashMetadata       hashMetadata
	EncryptionMetadata encryptionMetadata
}

func (f *fileMetadata) validate() error {
	if f.Version != 0 {
		return fmt.Errorf("bad version")
	}
	if err := f.HashMetadata.validate(); err != nil {
		return err
	}
	return f.EncryptionMetadata.validate()
}
