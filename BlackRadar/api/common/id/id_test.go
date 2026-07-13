package id

import (
	"regexp"
	"testing"
)

func TestNew(t *testing.T) {
	identifier, err := New()
	if err != nil {
		t.Fatalf("expected random ID generation to succeed, got %v", err)
	}

	if identifier == "" || len(identifier) != 36 {
		t.Fatalf("expected UUID random id, got %q", identifier)
	}

	uuidV4Pattern := regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	if !uuidV4Pattern.MatchString(identifier) {
		t.Fatalf("expected UUID v4 format, got %q", identifier)
	}
}
