package sym

type Option interface {
	EncryptFileOption
	DecryptFileOption
}

type forceOption bool

func (force forceOption) encryptOpt(opts *encryptOptions) {
	opts.force = bool(force)
}

func (force forceOption) decryptOpt(opts *decryptOptions) {
	opts.force = bool(force)
}

func Force(force bool) Option {
	return forceOption(force)
}
