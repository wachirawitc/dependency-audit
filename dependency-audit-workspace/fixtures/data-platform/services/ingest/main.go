package main

import (
	"net/http"

	"git.acme.internal/platform/auth"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Use(auth.Middleware())
	r.POST("/events", func(c *gin.Context) {
		var body map[string]any
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusAccepted)
	})
	_ = r.Run(":8080")
}
