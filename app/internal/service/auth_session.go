package service

import (
	"context"
	"errors"
	"fmt"

	"auth/internal/model"
)

func (a *Auth) issueSession(ctx context.Context, verified *model.User) (TokenPair, error) {
	var pair TokenPair
	err := a.store.WithSessionTransaction(ctx, verified.ID, func(current *model.User, writer SessionWriter) error {
		if !current.Enabled || current.Password != verified.Password {
			return ErrInvalidCredentials
		}

		if err := a.pruneStoredSessions(ctx, writer, current.ID, true); err != nil {
			return err
		}
		issued, err := a.tokens.Issue(current)
		if err != nil {
			return err
		}
		if err := writer.SaveToken(ctx, issued); err != nil {
			return err
		}

		pair = issued
		return nil
	})
	if errors.Is(err, ErrUserNotFound) {
		return TokenPair{}, ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, fmt.Errorf("persist session: %w", err)
	}

	return pair, nil
}

func (a *Auth) RefreshSession(ctx context.Context, refreshToken string) (TokenPair, error) {
	userID, err := a.tokens.Validate(refreshToken, RefreshToken)
	if err != nil {
		return TokenPair{}, err
	}

	var pair TokenPair
	err = a.store.WithSessionTransaction(ctx, userID, func(user *model.User, writer SessionWriter) error {
		if !user.Enabled {
			return ErrInvalidToken
		}
		id, err := a.tokens.Validate(refreshToken, RefreshToken)
		if err != nil {
			return err
		}
		if id != user.ID {
			return ErrInvalidToken
		}
		previous, err := writer.FindRefreshToken(ctx, refreshToken)
		if err != nil {
			return err
		}

		if err := a.pruneStoredSessions(ctx, writer, user.ID, false); err != nil {
			return err
		}
		issued, err := a.tokens.Issue(user)
		if err != nil {
			return err
		}
		updated, err := writer.ReplaceToken(ctx, previous, issued)
		if err != nil {
			return err
		}
		if !updated {
			return ErrInvalidToken
		}

		pair = issued
		return nil
	})
	if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrSessionNotFound) {
		return TokenPair{}, ErrInvalidToken
	}
	if err != nil {
		return TokenPair{}, fmt.Errorf("rotate session: %w", err)
	}

	return pair, nil
}

func (a *Auth) pruneStoredSessions(ctx context.Context, writer SessionWriter, userID uint, retainForLogin bool) error {
	var after uint
	newest := make([]uint, 0, 4)
	for {
		rows, err := writer.TokensAfter(ctx, after)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}

		remove := make([]uint, 0, len(rows))
		for _, row := range rows {
			current, err := a.tokens.MatchesSessionContract(userID, TokenPair{AccessToken: row.AccessToken, RefreshToken: row.RefreshToken})
			if err != nil {
				return err
			}
			if !current {
				remove = append(remove, row.ID)
			} else if retainForLogin {
				if len(newest) == 4 {
					remove = append(remove, newest[0])
					newest = newest[1:]
				}
				newest = append(newest, row.ID)
			}
		}
		if len(remove) > 0 {
			if err := writer.DeleteTokenIDs(ctx, remove); err != nil {
				return err
			}
		}

		after = rows[len(rows)-1].ID
	}
}
