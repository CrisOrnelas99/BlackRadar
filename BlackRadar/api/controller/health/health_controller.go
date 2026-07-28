// Package health provides the API health check controller.
package health

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ReadinessChecker reports whether the application dependencies are ready.
type ReadinessChecker interface {
	/*
		Ping checks the backing dependency using the request context and returns
		an error when the application is not ready to serve requests.
	*/
	Ping(context.Context) error
}

// Health returns a basic status response for health checks.
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready returns readiness based on database connectivity.
func Ready(database ReadinessChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if database == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}

		if err := database.Ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}
