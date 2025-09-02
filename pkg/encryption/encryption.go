package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

func GenerateEncryption(secretJson, outputPath string) {
	fmt.Println("--- 2FA Secrets Encryptor ---")

	plaintext, err := os.ReadFile(secretJson)
	if err != nil {
		panic(fmt.Sprintf("Failed to read secrets file: %v. Make sure the file exists in the parent directory.", err))
	}

	fmt.Print("Enter encryption password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(fmt.Sprintf("Failed to read password: %v", err))
	}
	fmt.Println()

	// Derive a strong key from the password using Scrypt
	// The salt is random and will be stored with the ciphertext
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32) // 32-byte key for AES-256
	if err != nil {
		panic(err)
	}

	// Encrypt the data using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// Seal will encrypt and authenticate the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	var outputFile string

	if outputPath != "" {
		outputFile = outputPath+"/secrets.enc"
	} else {
		outputFile = "secrets.enc"
	}

	// Write the salt + ciphertext to the output file
	finalPayload := append(salt, ciphertext...)
	err = os.WriteFile(outputFile, finalPayload, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to write to %s: %v", outputFile, err))
	}

	fmt.Printf("\nSuccessfully encrypted secrets.json -> %s\n", outputFile)
	fmt.Println("You can now safely delete secrets.json.")
}