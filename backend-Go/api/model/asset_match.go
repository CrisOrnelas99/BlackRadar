// Package model defines the persistence and domain structs used by GORM.
package model

// AssetCPEReviewStatus values describe how a product match was handled.
const (
	AssetCPEReviewStatusAccepted    = "accepted"
	AssetCPEReviewStatusNeedsReview = "needs_review"
	AssetCPEReviewStatusRejected    = "rejected"
)
