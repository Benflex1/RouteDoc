package main

import (
	"os"
)

func main() {
	app := NewApp(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.ReadFile)
	os.Exit(app.Run())
}
