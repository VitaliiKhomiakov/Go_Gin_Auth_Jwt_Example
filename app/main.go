package main

import (
	"errors"
	"log"
	"os"

	"auth/internal"
	"auth/internal/system/database"

	"github.com/gin-gonic/gin"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	if err := internal.Init(r); err != nil {
		return err
	}

	pool, err := database.DB.DB()
	if err != nil {
		return errors.New("database connection pool is unavailable")
	}
	defer func() {
		if err := pool.Close(); err != nil {
			log.Print("database connection pool could not be closed")
		}
	}()

	if err := r.Run(":8001"); err != nil {
		return errors.New("HTTP server failed to listen or serve")
	}

	return nil
}
