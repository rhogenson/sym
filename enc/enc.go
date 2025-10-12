package main

import (
	"flag"
	"fmt"
	"os"

	"roseh.moe/cmd/sym/internal/sym"
)

func main() {
	o := sym.DefaultEncryptOptions
	o.RegisterFlags(flag.CommandLine)
	flag.Parse()
	if err := o.Run(flag.Args()...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
