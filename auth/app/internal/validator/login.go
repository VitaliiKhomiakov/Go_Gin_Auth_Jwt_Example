package validator

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Login struct {
	EmailOrPhone string `json:"emailOrPhone" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

func LoginValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginUser Login

		if err := c.ShouldBindJSON(&loginUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect credentials", "message": err.Error()})
			c.Abort()
			return
		}

		c.Set("loginUser", loginUser)
	}
}
