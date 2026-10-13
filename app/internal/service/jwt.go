package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"auth/internal/model"
	"auth/internal/service/config"

	"github.com/dgrijalva/jwt-go"
)

type TokenType string

const (
	AccessToken  TokenType = "ACCESS_TOKEN"
	RefreshToken TokenType = "REFRESH_TOKEN"
)

type jwtUser struct {
	ID         uint      `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"firstName"`
	MiddleName string    `json:"middleName"`
	LastName   string    `json:"lastName"`
	Birthday   time.Time `json:"birthday"`
}

type tokenClaims struct {
	UserID    uint      `json:"userID"`
	ExpiresAt int64     `json:"exp"`
	TokenType TokenType `json:"tokenType"`
	ID        string    `json:"jti"`
	User      *jwtUser  `json:"user,omitempty"`
	now       int64
}

func (c tokenClaims) Valid() error {
	if c.UserID == 0 || c.ExpiresAt <= c.now || strings.TrimSpace(c.ID) == "" {
		return ErrInvalidToken
	}

	if c.TokenType != AccessToken && c.TokenType != RefreshToken {
		return ErrInvalidToken
	}

	return nil
}

type JWTCodec struct {
	keys config.SecretParams
	now  func() time.Time
}

func NewJWTCodec(keys config.SecretParams) (*JWTCodec, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}

	return &JWTCodec{keys: keys, now: time.Now}, nil
}

func (c JWTCodec) Issue(user *model.User) (TokenPair, error) {
	access, err := c.generateAccessToken(user)
	if err != nil {
		return TokenPair{}, err
	}

	refresh, err := c.sign(user.ID, RefreshToken, nil)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func (c JWTCodec) generateAccessToken(user *model.User) (string, error) {
	if user == nil {
		return "", errors.New("token issuance requires a user")
	}

	return c.sign(user.ID, AccessToken, &jwtUser{
		ID: user.ID, Email: user.Email, FirstName: user.FirstName,
		MiddleName: user.MiddleName, LastName: user.LastName, Birthday: user.Birthday,
	})
}

func (c JWTCodec) sign(userID uint, tokenType TokenType, user *jwtUser) (string, error) {
	key, err := c.signingKey(tokenType)
	if err != nil {
		return "", err
	}

	if userID == 0 {
		return "", errors.New("token issuance requires a positive user ID")
	}

	now := c.now()
	expiresAt := now.Add(15 * time.Minute)
	if tokenType == RefreshToken {
		expiresAt = now.AddDate(0, 1, 0)
	}

	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", errors.New("token identifier could not be generated")
	}

	claims := tokenClaims{
		UserID:    userID,
		ExpiresAt: expiresAt.Unix(),
		TokenType: tokenType,
		ID:        hex.EncodeToString(id[:]),
		User:      user,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		return "", errors.New("token could not be signed")
	}

	return token, nil
}

func (c JWTCodec) signingKey(tokenType TokenType) ([]byte, error) {
	if err := c.keys.Validate(); err != nil {
		return nil, err
	}

	switch tokenType {
	case AccessToken:
		return []byte(c.keys.AccessSecretKey), nil
	case RefreshToken:
		return []byte(c.keys.RefreshSecretKey), nil
	default:
		return nil, ErrInvalidToken
	}
}

func (c JWTCodec) Validate(tokenString string, tokenType TokenType) (uint, error) {
	key, err := c.signingKey(tokenType)
	if err != nil {
		return 0, err
	}

	claims := tokenClaims{now: c.now().Unix()}
	parser := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Alg()}}
	token, err := parser.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}

		return key, nil
	})
	if err != nil || !token.Valid || claims.TokenType != tokenType {
		return 0, ErrInvalidToken
	}

	return claims.UserID, nil
}
