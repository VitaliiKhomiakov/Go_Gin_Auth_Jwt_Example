package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth/internal/model"
)

type AuthStore interface {
	FindUserByEmail(context.Context, string) (model.User, error)
	FindUserByID(context.Context, uint) (*model.User, error)
	CreateUser(context.Context, *model.User) error
	// UpdatePasswordIfCurrent reports whether the credential matched and was replaced.
	UpdatePasswordIfCurrent(ctx context.Context, userID uint, current, replacement string) (bool, error)
	HasAccessToken(context.Context, uint, string) (bool, error)
	WithSessionTransaction(context.Context, uint, func(*model.User, SessionWriter) error) error
}

// SessionWriter is valid only within the transaction callback that supplies it.
type SessionWriter interface {
	TokensAfter(context.Context, uint) ([]model.Token, error)
	DeleteTokenIDs(context.Context, []uint) error
	SaveToken(context.Context, TokenPair) error
	FindRefreshToken(context.Context, string) (model.Token, error)
	ReplaceToken(context.Context, model.Token, TokenPair) (bool, error)
}

type TokenCodec interface {
	Issue(*model.User) (TokenPair, error)
	Validate(string, TokenType) (uint, error)
	MatchesSessionContract(uint, TokenPair) (bool, error)
}

type Auth struct {
	store  AuthStore
	tokens TokenCodec
}

func NewAuth(store AuthStore, tokens TokenCodec) *Auth {
	return &Auth{store: store, tokens: tokens}
}

func (a *Auth) SignIn(ctx context.Context, email, password string) (TokenPair, error) {
	user, err := a.store.FindUserByEmail(ctx, email)
	if errors.Is(err, ErrUserNotFound) {
		return TokenPair{}, ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, fmt.Errorf("find sign-in user: %w", err)
	}
	if !user.Enabled {
		return TokenPair{}, ErrInvalidCredentials
	}

	valid, needsUpgrade, err := VerifyPassword(password, user.Password)
	if err != nil {
		return TokenPair{}, fmt.Errorf("check password: %w", err)
	}
	if !valid {
		return TokenPair{}, ErrInvalidCredentials
	}

	if needsUpgrade {
		current, err := a.upgradePassword(ctx, &user, password)
		if err != nil {
			return TokenPair{}, err
		}
		return a.issueSession(ctx, current)
	}

	return a.issueSession(ctx, &user)
}

func (a *Auth) upgradePassword(ctx context.Context, user *model.User, password string) (*model.User, error) {
	encoded, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash upgraded password: %w", err)
	}

	updated, err := a.store.UpdatePasswordIfCurrent(ctx, user.ID, user.Password, encoded)
	if err != nil {
		return nil, fmt.Errorf("update legacy password: %w", err)
	}
	if updated {
		user.Password = encoded
		return user, nil
	}

	current, err := a.store.FindUserByID(ctx, user.ID)
	if errors.Is(err, ErrUserNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("reload sign-in user: %w", err)
	}
	if !current.Enabled {
		return nil, ErrInvalidCredentials
	}

	valid, needsUpgrade, err := VerifyPassword(password, current.Password)
	if err != nil {
		return nil, fmt.Errorf("check current password: %w", err)
	}
	if !valid {
		return nil, ErrInvalidCredentials
	}
	if needsUpgrade {
		return nil, errors.New("password upgrade did not establish a current credential")
	}

	return current, nil
}

func (a *Auth) AuthenticateAccessToken(ctx context.Context, accessToken string) (*model.User, error) {
	userID, err := a.tokens.Validate(accessToken, AccessToken)
	if err != nil {
		return nil, err
	}

	user, err := a.store.FindUserByID(ctx, userID)
	if errors.Is(err, ErrUserNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("find access user: %w", err)
	}
	if !user.Enabled {
		return nil, ErrInvalidToken
	}

	present, err := a.store.HasAccessToken(ctx, userID, accessToken)
	if err != nil {
		return nil, fmt.Errorf("find access session: %w", err)
	}
	if !present {
		return nil, ErrInvalidToken
	}

	return user, nil
}

func (a *Auth) SignUp(ctx context.Context, input SignUpInput) (UserWithoutSecret, error) {
	var birthday time.Time
	if input.Birthday != "" {
		var err error
		birthday, err = time.Parse("2006-01-02", input.Birthday)
		if err != nil {
			return UserWithoutSecret{}, ErrInvalidInput
		}
	}

	password, err := HashPassword(input.Password)
	if err != nil {
		return UserWithoutSecret{}, fmt.Errorf("hash signup password: %w", err)
	}
	user := model.User{
		Email: input.Email, Password: password, FirstName: input.FirstName,
		MiddleName: input.MiddleName, LastName: input.LastName, Birthday: birthday,
		Roles: `["STANDARD_USER"]`, Enabled: true,
	}
	if err := a.store.CreateUser(ctx, &user); err != nil {
		return UserWithoutSecret{}, fmt.Errorf("create signup user: %w", err)
	}

	return toPublicUser(&user), nil
}
