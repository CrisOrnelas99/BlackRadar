package risk_backfill

type RiskBackfillError struct {
	Message string
}

func (e RiskBackfillError) Error() string {
	return e.Message
}

var (
	ErrDatabaseRequired = &RiskBackfillError{Message: "asset risk backfill requires a database connection"}
	ErrLoadAssetsFailed = &RiskBackfillError{Message: "asset risk backfill failed to load assets"}
	ErrRefreshFailed    = &RiskBackfillError{Message: "asset risk backfill failed to refresh asset risk"}
)
