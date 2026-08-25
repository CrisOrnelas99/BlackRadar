// Package health provides the API health check controller.
package health

import (
	"context"
	"net/http"
	"time"

	servicehealth "blackradar/api/service/health"
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

type componentStatus struct {
	Status string `json:"status"`
}
type summaryResponse struct {
	Overall     string          `json:"overall"`
	CheckedAt   time.Time       `json:"checkedAt"`
	Application componentStatus `json:"application"`
	Database    componentStatus `json:"database"`
	AI          componentStatus `json:"ai"`
	NVD         componentStatus `json:"nvd"`
}

// Summary returns a safe administrator-only dependency summary.
func Summary(summaryChecker *servicehealth.SummaryChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		summary := summaryChecker.Check(c.Request.Context())
		c.JSON(http.StatusOK, summaryResponse{
			Overall:     string(summary.Overall),
			CheckedAt:   time.Now().UTC(),
			Application: componentStatus{Status: string(summary.Application)},
			Database:    componentStatus{Status: string(summary.Database)},
			AI:          componentStatus{Status: string(summary.AI)},
			NVD:         componentStatus{Status: string(summary.NVD)},
		})
	}
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
