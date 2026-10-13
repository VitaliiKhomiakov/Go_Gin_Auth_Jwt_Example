package service

import (
	"context"

	"auth/internal/model"
)

type AuthStore interface {
	FindUserByEmail(context.Context, string) (model.User, error)
	FindUserByID(context.Context, uint) (*model.User, error)
	CreateUser(context.Context, *model.User) error
	// UpdatePasswordIfCurrent reports whether the credential matched and was replaced.
	UpdatePasswordIfCurrent(ctx context.Context, userID uint, current, replacement string) (bool, error)
	WithSessionTransaction(context.Context, func(SessionWriter) error) error
}

// SessionWriter is valid only within the transaction callback that supplies it.
type SessionWriter interface {
	CountTokens(context.Context, uint) (int64, error)
	DeleteTokens(context.Context, uint) error
	SaveToken(context.Context, *model.Token) error
}

type TokenCodec interface {
	Issue(*model.User) (TokenPair, error)
	Validate(string, TokenType) (uint, error)
}
