package handler

import (
	"context"
	"net/http"

	"auth/internal/model"
	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthService interface {
	SignIn(context.Context, string, string) (service.TokenPair, error)
	RefreshSession(context.Context, string) (service.TokenPair, error)
	SignUp(context.Context, service.SignUpInput) (service.UserWithoutSecret, error)
}

type Auth struct {
	auth AuthService
}

func NewAuth(auth AuthService) *Auth {
	return &Auth{auth: auth}
}

func (h *Auth) Login(c *gin.Context) {
	var input loginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Incorrect credentials"})
		return
	}

	pair, err := h.auth.SignIn(c.Request.Context(), input.EmailOrPhone, input.Password)
	if err != nil {
		writeAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, tokensResponse(pair))
}

func (h *Auth) Refresh(c *gin.Context) {
	var input refreshRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is incorrect"})
		return
	}

	pair, err := h.auth.RefreshSession(c.Request.Context(), input.RefreshToken)
	if err != nil {
		writeAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, tokensResponse(pair))
}

func (h *Auth) SignUp(c *gin.Context) {
	var input signUpRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Incorrect data"})
		return
	}
	if input.Password != input.ConfirmPassword {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Incorrect data", "message": "Passwords do not match"})
		return
	}

	user, err := h.auth.SignUp(c.Request.Context(), input.input())
	if err != nil {
		writeAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"item": publicUser(user)})
}

func (h *Auth) Me(c *gin.Context) {
	identity, exists := c.Get("user")
	user, ok := identity.(*model.User)
	if !exists || !ok || user == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email})
}
