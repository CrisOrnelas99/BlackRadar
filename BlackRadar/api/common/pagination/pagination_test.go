package pagination

import (
	"errors"
	"math"
	"testing"
)

func TestRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		wantErr error
	}{
		{name: "valid", request: Request{Page: 1, PageSize: DefaultPageSize}},
		{name: "invalid page", request: Request{Page: 0, PageSize: DefaultPageSize}, wantErr: ErrInvalidPage},
		{name: "invalid page size", request: Request{Page: 1}, wantErr: ErrInvalidPageSize},
		{name: "maximum safe offset", request: Request{Page: math.MaxInt/DefaultPageSize + 1, PageSize: DefaultPageSize}},
		{name: "offset overflow", request: Request{Page: math.MaxInt, PageSize: DefaultPageSize}, wantErr: ErrInvalidPage},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.request.Validate()
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("expected %v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestPageTotalPages(t *testing.T) {
	tests := []struct {
		name     string
		page     Page[string]
		expected int
	}{
		{name: "empty", page: Page[string]{PageSize: DefaultPageSize}, expected: 0},
		{name: "exact boundary", page: Page[string]{PageSize: DefaultPageSize, TotalCount: 12}, expected: 2},
		{name: "partial final page", page: Page[string]{PageSize: DefaultPageSize, TotalCount: 13}, expected: 3},
		{name: "maximum count", page: Page[string]{PageSize: DefaultPageSize, TotalCount: math.MaxInt64}, expected: int(1 + (math.MaxInt64-1)/DefaultPageSize)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := test.page.TotalPages(); actual != test.expected {
				t.Fatalf("expected %d pages, got %d", test.expected, actual)
			}
		})
	}
}

func TestPageMetadata(t *testing.T) {
	page := Page[string]{Page: 2, PageSize: DefaultPageSize, TotalCount: 13}

	metadata := page.Metadata()
	if metadata.Page != 2 || metadata.PageSize != DefaultPageSize || metadata.TotalCount != 13 || metadata.TotalPages != 3 {
		t.Fatalf("unexpected pagination metadata: %+v", metadata)
	}
}
