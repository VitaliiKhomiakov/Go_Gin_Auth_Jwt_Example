package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

type messageResponse struct {
	Message string `json:"message"`
}

type healthResponse struct {
	Database string `json:"DataBase"`
}

func Base(c *gin.Context) {
	c.JSON(http.StatusOK, messageResponse{Message: "It works"})
}

func NewHealth(check func(context.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		status := "OK"
		if err := check(c.Request.Context()); err != nil {
			status = "ERROR"
		}

		c.JSON(http.StatusOK, healthResponse{Database: status})
	}
}
