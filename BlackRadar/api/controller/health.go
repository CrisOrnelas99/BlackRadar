// Package controller provides the health check handler for the API.
package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Health returns a basic status response for health checks.
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
