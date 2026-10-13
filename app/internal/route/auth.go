package route

import (
	"auth/internal/controller"
	"auth/internal/middleware"
	"github.com/gin-gonic/gin"
)

func auth(r *gin.Engine) {
	r.POST("/auth/login", middleware.LoginMiddleware(), controller.Login)
	r.POST("/auth/signUp", middleware.SignUpMiddleware(), controller.SingUp)
	r.GET("/auth/validate", middleware.AuthMiddleware(), controller.Validate)
	r.POST("/auth/refresh", middleware.RefreshMiddleware(), controller.Refresh)
}
