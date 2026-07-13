// Package db provides database transaction helpers.
package db

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// WithinTransaction executes an operation inside a GORM transaction.
//
// Returning an error from operation rolls the transaction back. Returning nil
// commits the transaction.
func WithinTransaction(ctx context.Context, database *gorm.DB, operation func(tx *gorm.DB) error) error {
	if database == nil {
		return fmt.Errorf("database transaction: database is required")
	}
	if operation == nil {
		return fmt.Errorf("database transaction: operation is required")
	}

	if err := database.WithContext(ctx).Transaction(operation); err != nil {
		return fmt.Errorf("database transaction: %w", err)
	}

	return nil
}
