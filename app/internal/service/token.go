package service

import (
	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/service/config"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type TokenType string

const (
	AccessToken  TokenType = "ACCESS_TOKEN"
	RefreshToken TokenType = "REFRESH_TOKEN"
)

func GetTokenConfig() config.SecretParams {
	return config.Secret()
}

func GenerateAccessToken(user *model.User) (string, error) {
	accessTokenData := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": ExcludeSecret(user),
		"exp":  time.Now().Add(time.Minute * 15).Unix(),
	})

	accessToken, err := accessTokenData.SignedString([]byte(GetTokenConfig().AccessSecretKey))
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func CreateRefreshToken(userID uint) (string, error) {
	refreshTokenData := map[string]interface{}{
		"userID": userID,
		"exp":    time.Now().AddDate(0, 1, 0).Unix(),
	}

	refreshTokenClaims := jwt.MapClaims(refreshTokenData)
	refreshTokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims).SignedString([]byte(GetTokenConfig().RefreshSecretKey))
	if err != nil {
		return "", err
	}
	return refreshTokenString, nil
}

func RemoveExpiredToken(userID uint, accessToken string) error {
	err := repository.GetTokenRepository().RemoveExpiredToken(userID, accessToken)
	if err != nil {
		return err
	}

	return nil
}

func CleanToken(userID uint) error {
	tokenCount, err := repository.GetTokenRepository().GetTokenCount(userID)

	if err != nil {
		return err
	}

	if tokenCount > 5 {
		_, err = repository.GetTokenRepository().RemoveTokens(userID)
		return err
	}

	return nil
}

func SaveToken(token *model.Token) {
	_, _ = repository.GetTokenRepository().SaveToken(token)
}

func ValidateToken(tokenString string, tokenType TokenType) (float64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		var tokenValue string

		switch tokenType {
		case AccessToken:
			tokenValue = GetTokenConfig().AccessSecretKey
		case RefreshToken:
			tokenValue = GetTokenConfig().RefreshSecretKey
		}

		return []byte(tokenValue), nil
	})

	if err != nil {
		return 0, err
	}

	if !token.Valid {
		return 0, errors.New("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return 0, errors.New("token claims are invalid")
	}

	userId := claims["userID"].(float64)
	exp := int64(claims["exp"].(float64))

	if exp < time.Now().Unix() {
		_ = RemoveExpiredToken(uint(userId), tokenString)
		return 0, errors.New("token has expired")
	}

	return userId, nil
}
