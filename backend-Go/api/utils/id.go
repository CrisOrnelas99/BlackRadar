// Package utils provides database connection, migration, and error translation helpers.
package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// NewRandomID returns a positive, random int64 suitable for use as a public identifier.
func NewRandomID() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}

	id := int64(binary.LittleEndian.Uint64(b[:]) & 0x7fffffffffffffff)
	if id == 0 {
		return 1
	}
	return id
}

// IsPrimaryKeyViolation reports whether err is a unique-violation on a primary-key constraint.
func IsPrimaryKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}

	return strings.HasSuffix(strings.ToLower(pgErr.ConstraintName), "_pkey")
}
