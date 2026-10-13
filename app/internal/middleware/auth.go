package middleware

import (
	"auth/internal/repository"
	"auth/internal/service"
	"auth/internal/validator"
	"github.com/gin-gonic/gin"
	"net/http"
)

type RefreshToken struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

func SignUpMiddleware() gin.HandlerFunc {
	return validator.SingUpValidator()
}

func LoginMiddleware() gin.HandlerFunc {
	validatorHandler := validator.LoginValidator()

	return func(c *gin.Context) {
		validatorHandler(c)
		loginUser := c.MustGet("loginUser").(validator.Login)
		user, err := service.Authenticate(loginUser.EmailOrPhone, loginUser.Password)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
		}

		c.Set("user", user)
		c.Next()
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		tokenString := authHeader[len("Bearer "):]

		userId, err := service.ValidateToken(tokenString, service.AccessToken)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		user, err := repository.GetUserRepository().GetUserByID(uint(userId))

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

func RefreshMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var refreshToken RefreshToken

		if err := c.ShouldBindJSON(&refreshToken); err != nil {
			service.GetErrorService(c).SendError(http.StatusUnauthorized, "auth.refresh_token_incorrect", "Refresh token is incorrect")
			c.Abort()
			return
		}

		userId, err := service.ValidateToken(refreshToken.RefreshToken, service.RefreshToken)

		if err != nil {
			service.GetErrorService(c).SendError(http.StatusUnauthorized, "auth.refresh_token_invalid", err.Error())
			c.Abort()
			return
		}

		c.Set("userId", userId)
		c.Next()
	}
}
