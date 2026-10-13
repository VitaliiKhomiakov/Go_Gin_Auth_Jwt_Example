package internal

import (
	"auth/internal/route"
	"auth/internal/service/config"
	"auth/internal/system/database"

	"github.com/gin-gonic/gin"
)

func Init(r *gin.Engine) error {
	conf, err := config.LoadDB()
	if err != nil {
		return err
	}

	connection, err := database.Open(conf)
	if err != nil {
		return err
	}
	database.DB = connection

	route.InitRoute(r)

	return nil
}
