package providerusage

import providerquota "blackradar/api/external/provider_quota"

// RepositoryInterface defines the provider usage persistence contract.
//
// The repository embeds the shared provider quota capability so the runtime
// can depend on the repository contract without duplicating Reserve's method
// definition.
type RepositoryInterface interface {
	providerquota.Reserver
}
