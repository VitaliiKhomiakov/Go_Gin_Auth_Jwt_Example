package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDBPasswordOverride(t *testing.T) {
	withDBConfig(t, validDBConfig)
	t.Setenv("AUTH_DB_PASSWORD", "override-fixture")

	params, err := LoadDB()
	if err != nil {
		t.Fatal("valid password override was rejected")
	}

	if params.Password != "override-fixture" {
		t.Fatal("database password override was ignored")
	}
}

func TestLoadDBPasswordFallback(t *testing.T) {
	withDBConfig(t, validDBConfig)
	withoutPasswordOverride(t)

	params, err := LoadDB()
	if err != nil {
		t.Fatal("valid TOML configuration was rejected")
	}

	if params.Password != "toml-fixture" || params.Host != "localhost" || params.Port != "5432" || params.Username != "fixture-user" || params.DbName != "fixture-db" {
		t.Fatal("TOML configuration was not preserved")
	}
}

func TestLoadDBRejectsEmptyOverride(t *testing.T) {
	withDBConfig(t, validDBConfig)
	t.Setenv("AUTH_DB_PASSWORD", "")

	if _, err := LoadDB(); err == nil {
		t.Fatal("empty override must not fall back to TOML")
	}
}

func TestLoadDBRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name     string
		contents string
	}{
		{"bad TOML", validDBConfig + "secret-fixture = \"unterminated"},
		{"missing host", strings.Replace(validDBConfig, `host = "localhost"`, `host = ""`, 1)},
		{"missing port", strings.Replace(validDBConfig, `port = "5432"`, `port = ""`, 1)},
		{"missing username", strings.Replace(validDBConfig, `username = "fixture-user"`, `username = ""`, 1)},
		{"missing password", strings.Replace(validDBConfig, `password = "toml-fixture"`, `password = ""`, 1)},
		{"missing database", strings.Replace(validDBConfig, `dbName = "fixture-db"`, `dbName = ""`, 1)},
		{"invalid port", strings.Replace(validDBConfig, `port = "5432"`, `port = "secret-fixture"`, 1)},
		{"out of range port", strings.Replace(validDBConfig, `port = "5432"`, `port = "65536"`, 1)},
		{"missing section", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withDBConfig(t, tc.contents)
			withoutPasswordOverride(t)

			params, err := LoadDB()
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}

			if params != (DBParams{}) {
				t.Fatal("failed load returned database credentials")
			}

			for _, secret := range []string{"secret-fixture", "toml-fixture", "fixture-user", "fixture-db"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("configuration error exposed a configuration value")
				}
			}
		})
	}
}

func TestLoadDBMissingFile(t *testing.T) {
	withDBConfig(t, validDBConfig)
	if err := os.Remove(filepath.Join("config", "db.toml")); err != nil {
		t.Fatal("cannot remove test configuration")
	}

	if _, err := LoadDB(); err == nil {
		t.Fatal("missing configuration file was accepted")
	}
}

func withoutPasswordOverride(t *testing.T) {
	t.Helper()

	t.Setenv("AUTH_DB_PASSWORD", "")
	if err := os.Unsetenv("AUTH_DB_PASSWORD"); err != nil {
		t.Fatal("cannot clear test override")
	}
}

const validDBConfig = `[main_database]
host = "localhost"
port = "5432"
username = "fixture-user"
password = "toml-fixture"
dbName = "fixture-db"
`

func withDBConfig(t *testing.T, contents string) {
	t.Helper()

	original, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot inspect test working directory")
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0700); err != nil {
		t.Fatal("cannot create test configuration directory")
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "db.toml"), []byte(contents), 0600); err != nil {
		t.Fatal("cannot create test configuration")
	}

	if err := os.Chdir(dir); err != nil {
		t.Fatal("cannot enter test directory")
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error("cannot restore test working directory")
		}
	})
}
