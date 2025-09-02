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

func GenerateEncryption() {
	fmt.Println("--- 2FA Secrets Encryptor ---")

	plaintext, err := os.ReadFile(os.Args[2])
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

	// Write the salt + ciphertext to the output file
	finalPayload := append(salt, ciphertext...)
	err = os.WriteFile("../secrets.enc", finalPayload, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to write to secrets.enc: %v", err))
	}

	fmt.Println("\nSuccessfully encrypted secrets.json -> secrets.enc")
	fmt.Println("You can now safely delete secrets.json.")
}