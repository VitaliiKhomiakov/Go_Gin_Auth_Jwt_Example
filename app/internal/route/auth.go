package route

import (
	"auth/internal/handler"

	"github.com/gin-gonic/gin"
)

func auth(r *gin.Engine, h *handler.Auth, authenticate gin.HandlerFunc) {
	r.POST("/auth/login", h.Login)
	r.POST("/auth/signUp", h.SignUp)
	r.GET("/auth/me", authenticate, h.Me)
	r.POST("/auth/refresh", h.Refresh)
}
