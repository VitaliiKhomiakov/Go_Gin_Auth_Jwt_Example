package repository

import (
	"context"
	"errors"

	"auth/internal/model"
)

func (r *AuthStore) FindUserByEmail(ctx context.Context, email string) (model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).First(&user, "email = ?", email).Error; err != nil {
		return model.User{}, storageError(err)
	}

	return user, nil
}

func (r *AuthStore) FindUserByID(ctx context.Context, id uint) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).First(&user, id).Error; err != nil {
		return nil, storageError(err)
	}

	return &user, nil
}

func (r *AuthStore) CreateUser(ctx context.Context, user *model.User) error {
	result := r.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		return storageError(result.Error)
	}
	if result.RowsAffected != 1 {
		return errors.New("user insert did not create one row")
	}

	return nil
}

func (r *AuthStore) UpdatePasswordIfCurrent(ctx context.Context, userID uint, current, replacement string) (bool, error) {
	result := r.db.WithContext(ctx).Model(&model.User{}).
		Where("id = ? AND password = ?", userID, current).
		UpdateColumn("password", replacement)
	if result.Error != nil {
		return false, storageError(result.Error)
	}
	if result.RowsAffected > 1 {
		return false, errors.New("password update affected multiple users")
	}

	return result.RowsAffected == 1, nil
}
