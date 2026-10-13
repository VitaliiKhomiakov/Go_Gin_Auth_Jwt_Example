package repository

import (
	"context"
	"errors"

	"auth/internal/model"

	"gorm.io/gorm"
)

type sessionWriter struct {
	db *gorm.DB
}

func (w *sessionWriter) CountTokens(ctx context.Context, userID uint) (int64, error) {
	var count int64
	if err := w.db.WithContext(ctx).Model(&model.Token{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return 0, err
	}

	return count, nil
}

func (w *sessionWriter) DeleteTokens(ctx context.Context, userID uint) error {
	return w.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&model.Token{}).Error
}

func (w *sessionWriter) SaveToken(ctx context.Context, token *model.Token) error {
	result := w.db.WithContext(ctx).Create(token)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("token insert did not create one row")
	}

	return nil
}
