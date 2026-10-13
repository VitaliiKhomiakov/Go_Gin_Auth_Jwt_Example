package repository

import (
	"context"
	"errors"

	"auth/internal/model"
	"auth/internal/service"

	"gorm.io/gorm"
)

const sessionPageSize = 100

type sessionWriter struct {
	db     *gorm.DB
	userID uint
}

func (r *AuthStore) HasAccessToken(ctx context.Context, userID uint, token string) (bool, error) {
	var found model.Token
	err := r.db.WithContext(ctx).Select("id").Where("user_id = ? AND access_token = ?", userID, token).Take(&found).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}

	return err == nil, err
}

func (w *sessionWriter) TokensAfter(ctx context.Context, after uint) ([]model.Token, error) {
	var rows []model.Token
	err := w.db.WithContext(ctx).Where("user_id = ? AND id > ?", w.userID, after).Order("id ASC").Limit(sessionPageSize).Find(&rows).Error
	return rows, err
}

func (w *sessionWriter) DeleteTokenIDs(ctx context.Context, ids []uint) error {
	return w.db.WithContext(ctx).Where("user_id = ? AND id IN ?", w.userID, ids).Delete(&model.Token{}).Error
}

func (w *sessionWriter) SaveToken(ctx context.Context, pair service.TokenPair) error {
	token := model.Token{UserID: uint64(w.userID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken}
	result := w.db.WithContext(ctx).Create(&token)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("token insert did not create one row")
	}

	return nil
}

func (w *sessionWriter) FindRefreshToken(ctx context.Context, token string) (model.Token, error) {
	var row model.Token
	err := w.db.WithContext(ctx).Where("user_id = ? AND refresh_token = ?", w.userID, token).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.Token{}, service.ErrSessionNotFound
	}

	return row, err
}

func (w *sessionWriter) ReplaceToken(ctx context.Context, previous model.Token, pair service.TokenPair) (bool, error) {
	result := w.db.WithContext(ctx).Model(&model.Token{}).
		Where("user_id = ? AND id = ? AND access_token = ? AND refresh_token = ?", w.userID, previous.ID, previous.AccessToken, previous.RefreshToken).
		Select("access_token", "refresh_token").
		Updates(model.Token{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken})
	if result.Error != nil {
		return false, result.Error
	}

	return result.RowsAffected == 1, nil
}
