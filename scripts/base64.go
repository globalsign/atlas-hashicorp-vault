// This script acts as a polyfill for base64 util, we need this because its not available on windows and I don't want to pull in a new package manager
package main

import (
	"encoding/base64"
	"flag"
	"io"
	"os"
)

var (
	isDecode    = false
	stdEncoding = false
)

func init() {
	flag.BoolVar(&isDecode, "d", false, "Should Decode input")
	flag.BoolVar(&stdEncoding, "std", false, "Should use std encoding")
	flag.Parse()
}

func main() {
	inFile, outFile := os.Stdin, os.Stdout
	encoding := base64.URLEncoding
	if stdEncoding {
		encoding = base64.StdEncoding
	}

	var err error
	if isDecode {
		_, err = io.Copy(outFile, base64.NewDecoder(encoding, inFile))
	} else {
		_, err = io.Copy(base64.NewEncoder(encoding, outFile), inFile)
	}

	if err != nil {
		panic(err)
	}
}
