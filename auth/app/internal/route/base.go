package route

import (
	"auth/internal/controller"
	"github.com/gin-gonic/gin"
)

func InitRoute(r *gin.Engine) {
	base(r)
	auth(r)
}

func base(r *gin.Engine) {
	r.GET("/", controller.Base)
	r.GET("/health", controller.Health)
}
