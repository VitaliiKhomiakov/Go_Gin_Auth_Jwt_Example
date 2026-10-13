package repository

import (
	"context"
	"errors"

	"auth/internal/model"
	"auth/internal/service"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type AuthStore struct {
	db *gorm.DB
}

func NewAuthStore(db *gorm.DB) *AuthStore {
	return &AuthStore{db: db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})}
}

func (r *AuthStore) WithSessionTransaction(ctx context.Context, userID uint, operation func(*model.User, service.SessionWriter) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
			return storageError(err)
		}

		return operation(&user, &sessionWriter{db: tx, userID: userID})
	})
}

func storageError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return service.ErrUserNotFound
	}

	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" && postgresError.ConstraintName == "user_email_key" {
		return service.ErrEmailExists
	}

	return err
}
