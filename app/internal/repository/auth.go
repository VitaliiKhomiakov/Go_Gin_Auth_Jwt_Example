package repository

import (
	"context"
	"errors"

	"auth/internal/service"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type AuthStore struct {
	db *gorm.DB
}

func NewAuthStore(db *gorm.DB) *AuthStore {
	return &AuthStore{db: db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})}
}

func (r *AuthStore) WithSessionTransaction(ctx context.Context, operation func(service.SessionWriter) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return operation(&sessionWriter{db: tx})
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
