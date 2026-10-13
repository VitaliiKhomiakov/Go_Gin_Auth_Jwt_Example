package controller

import (
	"auth/internal/model"
	"auth/internal/service"
	"auth/internal/validator"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Login(c *gin.Context) {
	userData, exists := c.Get("user")
	user := userData.(*model.User)

	if !exists || user == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	accessToken, errAccessToken := service.GenerateAccessToken(user)
	if errAccessToken != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errAccessToken.Error()})
		return
	}

	refreshToken, errRefreshToken := service.CreateRefreshToken(user.ID)

	err := service.CleanToken(user.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	if errRefreshToken != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errRefreshToken.Error()})
		return
	}

	service.SaveToken(&model.Token{
		UserID:       uint64(user.ID),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func SingUp(c *gin.Context) {
	signUpUser := c.MustGet("signUpUser").(validator.SignUp)

	user, err := service.CreateUser(signUpUser)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"item": user,
	})
}

func Validate(c *gin.Context) {
	user := c.MustGet("user").(model.User)

	c.JSON(http.StatusOK, gin.H{
		"id":    user.ID,
		"email": user.Email,
	})
}

func Refresh(c *gin.Context) {
	userId := c.MustGet("userId").(float64)
	user, err := service.GetUserByID(uint(userId))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Set("user", user)
	Login(c)
}
