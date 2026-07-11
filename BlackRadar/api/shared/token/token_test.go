package token

import "testing"

func TestNewTokenID(t *testing.T) {
	tokenID := NewTokenID()

	if len(tokenID) != 32 {
		t.Fatalf("expected 32 hex characters, got %d", len(tokenID))
	}
	if tokenID == "00000000000000000000000000000000" {
		t.Fatal("expected token id to be random, got fallback value")
	}
}
