package validator

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type SignUp struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
	FirstName       string `json:"firstName" binding:"required"`
	MiddleName      string `json:"middleName"`
	LastName        string `json:"lastName" binding:"required"`
	Birthday        string `json:"birthday"`
}

func SingUpValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		var signUpUser SignUp

		if err := c.ShouldBindJSON(&signUpUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect data", "message": err.Error()})
			c.Abort()
			return
		}

		if signUpUser.Password != signUpUser.ConfirmPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect data", "message": "Passwords do not match"})
			c.Abort()
			return
		}

		c.Set("signUpUser", signUpUser)
		c.Next()
	}
}
