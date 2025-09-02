package cli

import (
	"flag"
)

func ParseFlags() (string, string) {
	var encryptSecret string
	var outputPath string

	flag.StringVar(&encryptSecret, "encrypt-secret", "", "Encrypts secret file")
	flag.StringVar(&outputPath, "output-path", "", "Path to the output file")
	flag.Parse()

	return encryptSecret, outputPath
}
