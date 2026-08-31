// Package pagination defines the shared data contract for bounded list queries.
package pagination

import (
	"errors"
	"math"
)

var (
	// ErrInvalidPage identifies a page number that cannot be queried safely.
	ErrInvalidPage = errors.New("page must be greater than zero")
	// ErrInvalidPageSize identifies a page size that cannot be queried safely.
	ErrInvalidPageSize = errors.New("page size must be greater than zero")
)

// DefaultPageSize is the consistent number of data rows returned by table pages.
const DefaultPageSize = 6

// Request identifies a validated, bounded page to retrieve.
type Request struct {
	Page     int `form:"page"`
	PageSize int `form:"-"`
}

// Validate checks that the page can be converted into a safe database offset.
func (r Request) Validate() error {
	if r.Page < 1 {
		return ErrInvalidPage
	}
	if r.PageSize < 1 {
		return ErrInvalidPageSize
	}
	if r.Page-1 > math.MaxInt/r.PageSize {
		return ErrInvalidPage
	}

	return nil
}

// Page contains page items and the total count from the same scoped query.
type Page[T any] struct {
	Items      []T
	Page       int
	PageSize   int
	TotalCount int64
}

// Metadata contains navigation details for a bounded result set.
type Metadata struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
	TotalCount int64 `json:"totalCount"`
	TotalPages int   `json:"totalPages"`
}

// TotalPages returns the number of valid pages for the result set.
func (p Page[T]) TotalPages() int {
	if p.TotalCount == 0 || p.PageSize < 1 {
		return 0
	}

	return int(1 + (p.TotalCount-1)/int64(p.PageSize))
}

// Metadata returns the navigation details for the page.
func (p Page[T]) Metadata() Metadata {
	return Metadata{
		Page:       p.Page,
		PageSize:   p.PageSize,
		TotalCount: p.TotalCount,
		TotalPages: p.TotalPages(),
	}
}
