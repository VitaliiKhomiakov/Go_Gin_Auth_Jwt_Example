package internal

import (
	"auth/internal/handler"
	"auth/internal/middleware"
	"auth/internal/repository"
	"auth/internal/route"
	"auth/internal/service"
	"auth/internal/service/config"
	"auth/internal/system/database"

	"github.com/gin-gonic/gin"
)

func Init(r *gin.Engine) error {
	keys, err := config.LoadSecret()
	if err != nil {
		return err
	}
	codec, err := service.NewJWTCodec(keys)
	if err != nil {
		return err
	}

	conf, err := config.LoadDB()
	if err != nil {
		return err
	}

	connection, err := database.Open(conf)
	if err != nil {
		return err
	}
	database.DB = connection

	pool, err := connection.DB()
	if err != nil {
		return err
	}
	auth := service.NewAuth(repository.NewAuthStore(connection), codec)
	route.InitRoute(r, handler.NewAuth(auth), middleware.AuthMiddleware(auth), handler.NewHealth(pool.PingContext))

	return nil
}
