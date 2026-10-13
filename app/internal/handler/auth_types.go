package handler

import (
	"time"

	"auth/internal/service"
)

type loginRequest struct {
	EmailOrPhone string `json:"emailOrPhone" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type signUpRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
	FirstName       string `json:"firstName" binding:"required"`
	MiddleName      string `json:"middleName"`
	LastName        string `json:"lastName" binding:"required"`
	Birthday        string `json:"birthday"`
}

func (r signUpRequest) input() service.SignUpInput {
	return service.SignUpInput{
		Email: r.Email, Password: r.Password, FirstName: r.FirstName,
		MiddleName: r.MiddleName, LastName: r.LastName, Birthday: r.Birthday,
	}
}

type tokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func tokensResponse(pair service.TokenPair) tokenResponse {
	return tokenResponse{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken}
}

type userResponse struct {
	ID         uint      `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"firstName"`
	MiddleName string    `json:"middleName"`
	LastName   string    `json:"lastName"`
	Birthday   time.Time `json:"birthday"`
}

func publicUser(user service.UserWithoutSecret) userResponse {
	return userResponse{
		ID: user.ID, Email: user.Email, FirstName: user.FirstName,
		MiddleName: user.MiddleName, LastName: user.LastName, Birthday: user.Birthday,
	}
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type signUpResponse struct {
	Item userResponse `json:"item"`
}

type identityResponse struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}
