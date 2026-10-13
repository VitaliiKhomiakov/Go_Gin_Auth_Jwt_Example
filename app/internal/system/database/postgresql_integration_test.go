//go:build integration

package database

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestStartupRequiresApplicationSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_DSN must identify an isolated disposable PostgreSQL database")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("cannot connect to isolated PostgreSQL fixture")
	}

	pool, err := db.DB()
	if err != nil {
		t.Fatal("cannot access fixture connection pool")
	}
	t.Cleanup(func() { pool.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err = db.WithContext(ctx).Connection(func(conn *gorm.DB) error {
		conn = conn.Session(&gorm.Session{NewDB: true})

		schema := fmt.Sprintf("startup_fixture_%d", time.Now().UnixNano())
		if err := conn.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
			t.Fatal("cannot create private fixture schema")
		}
		defer conn.Exec(`DROP SCHEMA "` + schema + `" CASCADE`)

		if err := conn.Exec(`SET search_path TO "` + schema + `"`).Error; err != nil {
			t.Fatal("cannot select private fixture schema")
		}
		defer conn.Exec("RESET search_path")

		if err := checkApplicationSchema(conn); err == nil {
			t.Fatal("startup accepted an empty schema")
		}

		sql, err := os.ReadFile("../../../../database/schema.sql")
		if err != nil {
			t.Fatal("cannot read the authoritative application schema fixture")
		}
		if err := conn.Exec(string(sql)).Error; err != nil {
			t.Fatal("cannot initialize private fixture schema")
		}

		if err := conn.Exec(`INSERT INTO "user" (email, password, roles) VALUES ('fixture@example.invalid', 'fixture-hash', '[]')`).Error; err != nil {
			t.Fatal("cannot seed fixture user")
		}

		for i := 0; i < 2; i++ {
			if err := checkApplicationSchema(conn); err != nil {
				t.Fatal("startup rejected the authoritative application schema")
			}
		}

		var count int64
		if err := conn.Table("user").Count(&count).Error; err != nil || count != 1 {
			t.Fatal("startup did not preserve existing users")
		}

		var usersExists bool
		if err := conn.Raw("SELECT to_regclass('users') IS NOT NULL").Scan(&usersExists).Error; err != nil || usersExists {
			t.Fatal("startup created or could not verify an unrelated users table")
		}

		if err := conn.Exec("ALTER TABLE token DROP COLUMN refresh_token").Error; err != nil {
			t.Fatal("cannot create missing-column fixture")
		}

		if err := checkApplicationSchema(conn); err == nil {
			t.Fatal("startup accepted a missing required column")
		}

		return nil
	})
	if err != nil {
		t.Fatal("isolated fixture connection failed")
	}
}
