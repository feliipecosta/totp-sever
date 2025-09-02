package main

import (
	"log"
	"net/http"
	"os"

	"github.com/feliipecosta/totp-server/pkg/api"
	"github.com/feliipecosta/totp-server/pkg/cli"
	"github.com/feliipecosta/totp-server/pkg/encryption"
	"github.com/feliipecosta/totp-server/pkg/models"
	"github.com/feliipecosta/totp-server/pkg/totp"
)

func main() {
	encryptSecret, outputPath := cli.ParseFlags()

	if encryptSecret != "" {
		encryption.GenerateEncryption(encryptSecret, outputPath)
		return
	} else {
		log.Fatalf("Usage: go run main.go --encrypt-secret <secrets.json>")
	}

	var err error
	encryptedData, err = os.ReadFile("secrets.enc")
	if err != nil {
		log.Fatalf("FATAL: secrets.enc not found. Please create it using the encrypt_tool. Error: %v", err)
	}

	http.HandleFunc("/", api.HandleIndex)
	http.HandleFunc("/unlock", api.HandleUnlock)
	http.HandleFunc("/api/codes", api.HandleAPICodes) // API endpoint for real-time updates

	port := "3450"
	log.Printf("Starting 2FA server on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}


