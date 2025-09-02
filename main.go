package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/scrypt"
)

type Account struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type TemplateData struct {
	Accounts []CodeDisplay
	Error    string
}

type CodeDisplay struct {
	Name string
	Code string
}

var (
	// In-memory store for decrypted accounts. Using a mutex for thread safety.
	decryptedAccounts []Account
	secretsMutex      = &sync.RWMutex{}
	templates         = template.Must(template.ParseFiles("templates/unlock.html", "templates/codes.html"))
	encryptedData     []byte
)

func main() {
	var err error
	encryptedData, err = os.ReadFile("secrets.enc")
	if err != nil {
		log.Fatalf("FATAL: secrets.enc not found. Please create it using the encrypt_tool. Error: %v", err)
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/unlock", handleUnlock)
	http.HandleFunc("/api/codes", handleAPICodes) // API endpoint for real-time updates

	port := "3450"
	log.Printf("Starting 2FA server on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	secretsMutex.Lock()
	decryptedAccounts = nil
	secretsMutex.Unlock()
	templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: ""})
}

func handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Password cannot be empty."})
		return
	}

	// Decrypt the data
	// Extract salt (first 32 bytes)
	salt := encryptedData[:32]
	ciphertext := encryptedData[32:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Printf("Error deriving key: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating GCM: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println("Ciphertext too short")
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Invalid password or corrupted data."})
		return
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This is the most likely error for a wrong password
		log.Printf("Decryption failed: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Invalid password or corrupted data."})
		return
	}

	// Successfully decrypted, now unmarshal and store in memory
	var accounts []Account
	if err := json.Unmarshal(plaintext, &accounts); err != nil {
		log.Printf("Failed to unmarshal secrets: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", TemplateData{Error: "Corrupted data format."})
		return
	}

	secretsMutex.Lock()
	decryptedAccounts = accounts
	secretsMutex.Unlock()

	log.Println("Secrets successfully decrypted and loaded into memory.")
	codes, err := generateCodes()
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}
	templates.ExecuteTemplate(w, "codes.html", TemplateData{Accounts: codes})
}

func handleAPICodes(w http.ResponseWriter, r *http.Request) {
	secretsMutex.RLock()
	isUnlocked := len(decryptedAccounts) > 0
	secretsMutex.RUnlock()

	if !isUnlocked {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	codes, err := generateCodes()
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

func generateCodes() ([]CodeDisplay, error) {
	secretsMutex.RLock()
	defer secretsMutex.RUnlock()

	var displayCodes []CodeDisplay
	for _, acc := range decryptedAccounts {
		code, err := totp.GenerateCode(acc.Secret, time.Now())
		if err != nil {
			log.Printf("Error generating code for %s: %v", acc.Name, err)
			// Still add it to the list to show an error in the UI
			displayCodes = append(displayCodes, CodeDisplay{Name: acc.Name, Code: "Error"}) 
		} else {
			displayCodes = append(displayCodes, CodeDisplay{Name: acc.Name, Code: code})
		}
	}
	return displayCodes, nil
}