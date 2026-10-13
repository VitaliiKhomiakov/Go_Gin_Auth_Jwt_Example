package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"auth/internal/model"
	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

type AccessAuthenticator interface {
	AuthenticateAccessToken(context.Context, string) (*model.User, error)
}

func AuthMiddleware(auth AccessAuthenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			return
		}

		fields := strings.Fields(header)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is invalid"})
			return
		}

		user, err := auth.AuthenticateAccessToken(c.Request.Context(), fields[1])
		if err != nil {
			status, message := http.StatusInternalServerError, "Internal server error"
			if errors.Is(err, service.ErrInvalidToken) {
				status, message = http.StatusUnauthorized, "Authentication failed"
			}

			c.AbortWithStatusJSON(status, gin.H{"error": message})
			return
		}
		if user == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		c.Set("user", user)
		c.Next()
	}
}
