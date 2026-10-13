package service

import "errors"

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type SignUpInput struct {
	Email      string
	Password   string
	FirstName  string
	MiddleName string
	LastName   string
	Birthday   string
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("token is invalid")
	ErrEmailExists        = errors.New("email already exists")
	ErrInvalidInput       = errors.New("invalid input")
)
