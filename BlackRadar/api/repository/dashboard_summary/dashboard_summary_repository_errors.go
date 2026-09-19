// Package dashboardsummary provides dashboard summary persistence operations.
package dashboardsummary

import "errors"

var (
	ErrRecordNotFound   = errors.New("dashboard summary not found")
	ErrPersistenceError = errors.New("dashboard summary persistence failed")
)
