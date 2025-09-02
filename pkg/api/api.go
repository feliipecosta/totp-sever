package api

import (
	"github.com/feliipecosta/totp-server/pkg/models"
	"github.com/feliipecosta/totp-server/pkg/totp"
)


var (
	templates         = template.Must(template.ParseFiles("templates/unlock.html", "templates/codes.html"))
	encryptedData     []byte
)

func HandleIndex(w http.ResponseWriter, r *http.Request) {
	secretsMutex.Lock()
	decryptedAccounts = nil
	secretsMutex.Unlock()
	templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: ""})
}

func HandleAPICodes(w http.ResponseWriter, r *http.Request) {
	secretsMutex.RLock()
	isUnlocked := len(decryptedAccounts) > 0
	secretsMutex.RUnlock()

	if !isUnlocked {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	codes, err := totp.GenerateCodes()
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

func HandleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Password cannot be empty."})
		return
	}

	// Decrypt the data
	// Extract salt (first 32 bytes)
	salt := encryptedData[:32]
	ciphertext := encryptedData[32:]

	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Printf("Error deriving key: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating GCM: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Decryption failed (internal error)."})
		return
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println("Ciphertext too short")
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Invalid password or corrupted data."})
		return
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This is the most likely error for a wrong password
		log.Printf("Decryption failed: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Invalid password or corrupted data."})
		return
	}

	// Successfully decrypted, now unmarshal and store in memory
	var accounts []models.Account
	if err := json.Unmarshal(plaintext, &accounts); err != nil {
		log.Printf("Failed to unmarshal secrets: %v", err)
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: "Corrupted data format."})
		return
	}

	secretsMutex.Lock()
	decryptedAccounts = accounts
	secretsMutex.Unlock()

	log.Println("Secrets successfully decrypted and loaded into memory.")
	codes, err := totp.GenerateCodes()
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}
	templates.ExecuteTemplate(w, "codes.html", models.TemplateData{Accounts: codes})
}
