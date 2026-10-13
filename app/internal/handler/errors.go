package handler

import (
	"errors"
	"net/http"

	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

func writeAuthError(c *gin.Context, err error) {
	status, message := http.StatusInternalServerError, "Internal server error"
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		status, message = http.StatusUnauthorized, "Incorrect credentials"
	case errors.Is(err, service.ErrInvalidToken):
		status, message = http.StatusUnauthorized, "Authentication failed"
	case errors.Is(err, service.ErrEmailExists):
		status, message = http.StatusConflict, "Email already exists"
	case errors.Is(err, service.ErrInvalidInput):
		status, message = http.StatusBadRequest, "Incorrect data"
	}

	c.AbortWithStatusJSON(status, gin.H{"error": message})
}
