package controller

import (
	"auth/internal/repository"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Base(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "It works",
	})
}

func Health(c *gin.Context) {
	var dbStatus string
	if err := repository.GetUserRepository().CheckDatabaseConnection(); err == nil {
		dbStatus = "OK"
	} else {
		dbStatus = "ERROR"
	}
	c.JSON(http.StatusOK, gin.H{
		"DataBase": dbStatus,
	})
}
