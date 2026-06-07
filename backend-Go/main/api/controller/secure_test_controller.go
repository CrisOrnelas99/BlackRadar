package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SecureTest(c *gin.Context) {
	c.String(http.StatusOK, "secure endpoint works")
}

