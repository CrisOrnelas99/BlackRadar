// Package token provides refresh token identifier helpers.
package token

import (
	"crypto/rand"
	"encoding/hex"
)

// NewTokenID returns a random hex string suitable for use as a refresh token session identifier.
func NewTokenID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}

	return hex.EncodeToString(b[:])
}
