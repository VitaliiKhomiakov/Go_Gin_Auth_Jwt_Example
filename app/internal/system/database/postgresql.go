package database

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"auth/internal/service/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Open(conf config.DBParams) (*gorm.DB, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	connection, err := gorm.Open(postgres.Open(connectionString(conf)), &gorm.Config{
		Logger:               logger.Default.LogMode(logger.Silent),
		DisableAutomaticPing: true,
	})
	if err != nil {
		if connection != nil {
			if pool, poolErr := connection.DB(); poolErr == nil {
				if closeErr := pool.Close(); closeErr != nil {
					log.Print("database connection pool could not be closed")
				}
			}
		}

		return nil, errors.New("database connection configuration failed")
	}

	pool, err := connection.DB()
	if err != nil {
		return nil, errors.New("database connection pool initialization failed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		if closeErr := pool.Close(); closeErr != nil {
			log.Print("database connection pool could not be closed")
		}

		return nil, fmt.Errorf("database connection failed: %s", failureCategory(err))
	}

	if err := checkApplicationSchema(connection.WithContext(ctx)); err != nil {
		if closeErr := pool.Close(); closeErr != nil {
			log.Print("database connection pool could not be closed")
		}

		return nil, err
	}

	return connection, nil
}

func connectionString(conf config.DBParams) string {
	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(conf.Username, conf.Password),
		Host:   net.JoinHostPort(conf.Host, conf.Port),
		Path:   "/" + conf.DbName,
	}

	query := url.Values{"sslmode": {"disable"}, "connect_timeout": {"10"}}
	dsn.RawQuery = query.Encode()

	return dsn.String()
}

func checkApplicationSchema(connection *gorm.DB) error {
	tables := []struct {
		name  string
		query string
	}{
		{"user", `SELECT id, email, password, roles, first_name, middle_name, last_name, birthday, last_login, enabled FROM "user" LIMIT 0`},
		{"token", `SELECT id, user_id, access_token, refresh_token FROM token LIMIT 0`},
	}
	for _, table := range tables {
		rows, err := connection.Raw(table.query).Rows()
		if err != nil {
			return fmt.Errorf("database schema check failed for %s: %s", table.name, failureCategory(err))
		}

		if err := rows.Close(); err != nil {
			return errors.New("database schema check could not finish")
		}
	}

	return nil
}

func failureCategory(err error) string {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "28P01", "28000":
			return "authentication rejected"
		case "3D000":
			return "database does not exist"
		case "42P01":
			return "required table is missing"
		case "42703":
			return "required column is missing"
		case "42501":
			return "permission denied"
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	var networkError net.Error
	if errors.As(err, &networkError) {
		return "network unavailable"
	}

	return "database operation failed"
}
