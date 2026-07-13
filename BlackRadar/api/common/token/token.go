// Package token provides cryptographically secure refresh-token identifier helpers.
package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const tokenIDByteLength = 32

// NewID returns a cryptographically secure random identifier suitable for
// identifying a refresh-token session.
func NewID() (string, error) {
	value := make([]byte, tokenIDByteLength)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate refresh token ID: %w", err)
	}

	return hex.EncodeToString(value), nil
}
