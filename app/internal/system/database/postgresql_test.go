package database

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"auth/internal/service/config"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm/logger"
)

func TestConnectionStringPreservesCredentials(t *testing.T) {
	params := config.DBParams{Host: "localhost", Port: "5432", Username: "fixture user", Password: "spaces 'quotes' \\ slash/@?#:%", DbName: "fixture-db"}

	parsed, err := pgx.ParseConfig(connectionString(params))
	if err != nil {
		t.Fatal("connection configuration was not parseable")
	}

	if parsed.Password != params.Password || parsed.User != params.Username || parsed.Database != params.DbName || parsed.Host != params.Host || parsed.Port != 5432 {
		t.Fatal("connection configuration changed credentials or connection fields")
	}
}

func TestOpenFailureIsSafe(t *testing.T) {
	var output bytes.Buffer
	original := logger.Default
	logger.Default = logger.New(log.New(&output, "", 0), logger.Config{LogLevel: logger.Warn})
	t.Cleanup(func() { logger.Default = original })

	params := config.DBParams{Host: "127.0.0.1", Port: "1", Username: "username-secret-fixture", Password: "password-secret-fixture", DbName: "dbname-secret-fixture"}
	db, err := Open(params)
	if err == nil || db != nil {
		t.Fatal("unreachable database was accepted")
	}

	for _, secret := range []string{params.Username, params.Password, params.DbName} {
		if strings.Contains(err.Error(), secret) || strings.Contains(output.String(), secret) {
			t.Fatal("database failure exposed credentials")
		}
	}
}
