package id

import (
	"testing"
)

func TestNew(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatalf("expected random ID generation to succeed, got %v", err)
	}

	if id == "" || len(id) != 36 {
		t.Fatalf("expected UUID random id, got %q", id)
	}
}
