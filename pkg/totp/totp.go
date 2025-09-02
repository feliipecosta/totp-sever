package totp

import (
	"github.com/feliipecosta/totp-server/pkg/models"
	"sync"
	"time"
)

var (
	secretsMutex      = &sync.RWMutex{}
	decryptedAccounts  []models.Account
)

func GenerateCodes() ([]models.CodeDisplay, error) {
	secretsMutex.RLock()
	defer secretsMutex.RUnlock()

	var displayCodes []models.CodeDisplay
	for _, acc := range decryptedAccounts {
		code, err := totp.GenerateCode(acc.Secret, time.Now())
		if err != nil {
			log.Printf("Error generating code for %s: %v", acc.Name, err)
			// Still add it to the list to show an error in the UI
			displayCodes = append(displayCodes, models.CodeDisplay{Name: acc.Name, Code: "Error"})
		} else {
			displayCodes = append(displayCodes, models.CodeDisplay{Name: acc.Name, Code: code})
		}
	}
	return displayCodes, nil
}