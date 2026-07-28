/*
Package transaction defines the application transaction boundary used by
services without exposing the database implementation to them.
*/
package transaction

import appcontext "blackradar/api/platform/requestcontext"

// Runner executes a request workflow with one transaction-scoped request context.
type Runner interface {
	/*
		Run executes operation with a transaction-scoped request context.

		Implementations must commit only when operation returns nil and must roll
		back when operation returns an error. A missing database must fail closed
		instead of executing the operation without atomicity.
	*/
	Run(ec *appcontext.GinContext, operation func(*appcontext.GinContext) error) error
}
