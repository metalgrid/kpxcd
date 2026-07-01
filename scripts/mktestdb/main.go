//go:build linux

// mktestdb creates an empty KeePass database for integration tests.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tobischo/gokeepasslib/v3"
)

func main() {
	path := flag.String("path", "", "output KDBX path")
	password := flag.String("password", "", "database password")
	flag.Parse()

	if *path == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "usage: mktestdb -path <kdbx> -password <pass>")
		os.Exit(2)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(*password)
	db.Content.Root.Groups[0].Name = "Root"

	f, err := os.Create(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := gokeepasslib.NewEncoder(f).Encode(db); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
