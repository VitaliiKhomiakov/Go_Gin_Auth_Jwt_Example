package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Base(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "It works"})
}

func NewHealth(check func(context.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		status := "OK"
		if err := check(c.Request.Context()); err != nil {
			status = "ERROR"
		}

		c.JSON(http.StatusOK, gin.H{"DataBase": status})
	}
}
