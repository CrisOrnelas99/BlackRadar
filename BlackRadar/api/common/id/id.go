// Package id provides cryptographically secure identifier helpers.
package id

import (
	"crypto/rand"
	"fmt"
)

// New returns a cryptographically secure random UUID version 4.
func New() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}

	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}
