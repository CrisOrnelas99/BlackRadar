package service

import (
	"errors"
	"fmt"

	"secureops/backend-go/api/repository"
)

func translateRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, repository.ErrAssetNotFound), errors.Is(err, repository.ErrVulnerabilityNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, repository.ErrDuplicateAssignment), errors.Is(err, repository.ErrInvalidReference):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case errors.Is(err, repository.ErrInvalidData):
		return fmt.Errorf("%w: %w", ErrInvalidRequestData, err)
	default:
		return err
	}
}

