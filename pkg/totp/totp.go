package totp

import (
	"log"
	"sync"
	"time"

	"github.com/feliipecosta/totp-server/pkg/models"
	"github.com/pquerna/otp/totp"
)

func GenerateCodes(decryptedAccounts []models.Account, secretsMutex *sync.RWMutex) ([]models.CodeDisplay, error) {
	secretsMutex.RLock()
	defer secretsMutex.RUnlock()

	// Create a slice of the correct size to store the results.
	// This allows each goroutine to write to a unique index without a mutex.
	displayCodes := make([]models.CodeDisplay, len(decryptedAccounts))
	
	// A WaitGroup is used to wait for all goroutines to finish their work.
	var wg sync.WaitGroup

	for i, acc := range decryptedAccounts {
		wg.Add(1) // Increment the WaitGroup counter.

		// Launch a new goroutine for each account.
		go func(index int, account models.Account) {
			defer wg.Done() // Decrement the counter when the goroutine completes.

			code, err := totp.GenerateCode(account.Secret, time.Now())
			if err != nil {
				log.Printf("Error generating code for %s: %v", account.Name, err)
				displayCodes[index] = models.CodeDisplay{Name: account.Name, Code: "Error"}
			} else {
				displayCodes[index] = models.CodeDisplay{Name: account.Name, Code: code}
			}
		}(i, acc) // Pass index and account as arguments to avoid closure issues.
	}

	wg.Wait() // Block until all goroutines have finished.

	return displayCodes, nil
}