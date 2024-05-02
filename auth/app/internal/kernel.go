package internal

import (
	"auth/internal/route"
	"auth/internal/system/database"
	"github.com/gin-gonic/gin"
)

func Init(r *gin.Engine) {
	database.Database()
	route.InitRoute(r)
}
