// Command trove is the Trove server and client in one binary.
package main

import (
	"os"

	"trove/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
