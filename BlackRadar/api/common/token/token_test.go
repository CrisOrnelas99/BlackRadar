package token

import "testing"

func TestNewID(t *testing.T) {
	tokenID, err := NewID()
	if err != nil {
		t.Fatalf("expected token ID generation to succeed, got %v", err)
	}

	if len(tokenID) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(tokenID))
	}
	if tokenID == "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatal("expected token ID to be random, got zero value")
	}
}
