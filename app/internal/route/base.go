package route

import (
	"auth/internal/handler"

	"github.com/gin-gonic/gin"
)

func InitRoute(r *gin.Engine, h *handler.Auth, authenticate gin.HandlerFunc, health gin.HandlerFunc) {
	r.GET("/", handler.Base)
	r.GET("/health", health)

	auth(r, h, authenticate)
}
