package main

import (
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/feliipecosta/totp-server/pkg/api"
	"github.com/feliipecosta/totp-server/pkg/cli"
	"github.com/feliipecosta/totp-server/pkg/encryption"
	"github.com/feliipecosta/totp-server/pkg/models"
)

var (
	secretsMutex      = &sync.RWMutex{}
	decryptedAccounts  *[]models.Account
	encryptedData     []byte
)

func main() {
	decryptedAccounts = new([]models.Account)
	encryptSecret, outputPath := cli.ParseFlags()

	if encryptSecret != "" {
		encryption.GenerateEncryption(encryptSecret, outputPath)
		return
	}

	var err error
	encryptedData, err = os.ReadFile("secrets.enc")
	if err != nil {
		log.Fatalf("FATAL: secrets.enc not found. Please create it using the encrypt_tool. Error: %v", err)
	}

	// CORRECT CODE
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// The router provides w and r, and we pass them along.
		api.HandleIndex(secretsMutex, decryptedAccounts, w, r)
	})

	http.HandleFunc("/unlock", func(w http.ResponseWriter, r *http.Request) {
		api.HandleUnlock(encryptedData, secretsMutex, decryptedAccounts, w, r)
	})

	http.HandleFunc("/api/codes", func(w http.ResponseWriter, r *http.Request) {
		api.HandleAPICodes(secretsMutex, decryptedAccounts, w, r)
	})

	port := "3450"
	log.Printf("Starting 2FA server on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
