package main

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

func main() {
	fmt.Println("--- 2FA Secrets Encryptor ---")

	// 1. Read the plaintext secrets file
	plaintext, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(fmt.Sprintf("Failed to read secrets file: %v. Make sure the file exists in the parent directory.", err))
	}

	// 2. Get password securely from terminal
	fmt.Print("Enter encryption password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(fmt.Sprintf("Failed to read password: %v", err))
	}
	fmt.Println() // Newline after password input

	// 3. Derive a strong key from the password using Scrypt
	// The salt is random and will be stored with the ciphertext
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	// Scrypt is a key derivation function that is computationally intensive
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32) // 32-byte key for AES-256
	if err != nil {
		panic(err)
	}

	// 4. Encrypt the data using AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Nonce needs to be unique for each encryption with the same key
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// Seal will encrypt and authenticate the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// 5. Write the salt + ciphertext to the output file
	// We store the salt so we can re-derive the same key for decryption
	finalPayload := append(salt, ciphertext...)
	err = os.WriteFile("../secrets.enc", finalPayload, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to write to secrets.enc: %v", err))
	}

	fmt.Println("\n✅ Successfully encrypted secrets.json -> secrets.enc")
	fmt.Println("You can now safely delete secrets.json.")
}