// Package id provides random public identifier helpers.
package id

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// NewRandomID returns a random UUID string suitable for use as a public identifier.
func NewRandomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000001"
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// IsPrimaryKeyViolation reports whether err is a unique-violation on a primary-key constraint.
func IsPrimaryKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}

	return strings.HasSuffix(strings.ToLower(pgErr.ConstraintName), "_pkey")
}
