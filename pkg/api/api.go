package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
	"github.com/feliipecosta/totp-server/pkg/models"
	"github.com/feliipecosta/totp-server/pkg/totp"
)

var (
	templates         = template.Must(template.ParseFiles("templates/unlock.html", "templates/codes.html"))
	sessionTimeout    time.Time
	sessionToken      string
	sessionMutex      sync.RWMutex
	lastAccessTime    time.Time
)

func HandleIndex(secretsMutex *sync.RWMutex, decryptedAccounts *[]models.Account, w http.ResponseWriter, r *http.Request) {
	// Check if user provided a session token (indicating they have an active session)
	providedToken := r.URL.Query().Get("token")
	
	sessionMutex.RLock()
	currentSessionToken := sessionToken
	sessionMutex.RUnlock()
	
	secretsMutex.RLock()
	isUnlocked := len(*decryptedAccounts) > 0 && time.Now().Before(sessionTimeout)
	secretsMutex.RUnlock()

	// If we have an active session but no valid token provided, it's a manual refresh
	if isUnlocked && (providedToken == "" || providedToken != currentSessionToken) {
		// Manual refresh detected - invalidate session and require re-auth
		secretsMutex.Lock()
		*decryptedAccounts = nil
		secretsMutex.Unlock()
		
		sessionMutex.Lock()
		sessionToken = ""
		sessionMutex.Unlock()
		
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: ""})
		return
	}

	if isUnlocked {
		// Update last access time
		sessionMutex.Lock()
		lastAccessTime = time.Now()
		sessionMutex.Unlock()
		
		codes, err := totp.GenerateCodes(*decryptedAccounts, secretsMutex)
		if err != nil {
			http.Error(w, "Could not generate codes", http.StatusInternalServerError)
			return
		}
		templates.ExecuteTemplate(w, "codes.html", models.TemplateData{Accounts: codes, SessionToken: currentSessionToken})
	} else {
		secretsMutex.Lock()
		*decryptedAccounts = nil
		secretsMutex.Unlock()
		templates.ExecuteTemplate(w, "unlock.html", models.TemplateData{Error: ""})
	}
}

// Helper function to check if referer contains unlock path
func containsUnlockPath(referer string) bool {
	if referer == "" {
		return false
	}
	if len(referer) >= 7 && referer[len(referer)-7:] == "/unlock" {
		return true
	}
	if len(referer) >= 1 && referer[len(referer)-1:] == "/" {
		return true
	}
	return false
}

func HandleAPICodes(secretsMutex *sync.RWMutex, decryptedAccounts *[]models.Account, w http.ResponseWriter, r *http.Request) {
	// Check session token for API calls too
	sessionTokenFromClient := r.Header.Get("X-Session-Token")
	
	sessionMutex.RLock()
	currentSessionToken := sessionToken
	sessionMutex.RUnlock()
	
	secretsMutex.RLock()
	isUnlocked := len(*decryptedAccounts) > 0 && time.Now().Before(sessionTimeout)
	secretsMutex.RUnlock()

	if !isUnlocked || sessionTokenFromClient != currentSessionToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Update last access time for API calls
	sessionMutex.Lock()
	lastAccessTime = time.Now()
	sessionMutex.Unlock()

	codes, err := totp.GenerateCodes(*decryptedAccounts, secretsMutex)
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

func HandleUnlock(encryptedData []byte, secretsMutex *sync.RWMutex, decryptedAccounts *[]models.Account, w http.ResponseWriter, r *http.Request) {
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
	*decryptedAccounts = accounts
	sessionTimeout = time.Now().Add(3 * time.Minute)
	secretsMutex.Unlock()

	// Generate a new session token
	sessionMutex.Lock()
	sessionToken = generateSessionToken()
	currentSessionToken := sessionToken
	lastAccessTime = time.Now()
	sessionMutex.Unlock()

	log.Println("Secrets successfully decrypted and loaded into memory.")
	codes, err := totp.GenerateCodes(*decryptedAccounts, secretsMutex)
	if err != nil {
		http.Error(w, "Could not generate codes", http.StatusInternalServerError)
		return
	}
	templates.ExecuteTemplate(w, "codes.html", models.TemplateData{Accounts: codes, SessionToken: currentSessionToken})
}

// generateSessionToken creates a random session token
func generateSessionToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
