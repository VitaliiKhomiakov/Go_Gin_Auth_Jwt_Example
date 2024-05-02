package service

import (
	"github.com/gin-gonic/gin"
)

type Error struct {
	c *gin.Context
}

type ErrorService interface {
	SendError(code int, err, message string)
}

func GetErrorService(c *gin.Context) ErrorService {
	return &Error{c: c}
}

func (e *Error) SendError(code int, err string, message string) {
	e.c.JSON(code, gin.H{"error": err, "message": message})
}
