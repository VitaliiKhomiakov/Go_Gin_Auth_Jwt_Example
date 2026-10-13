package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSecretConfig = "[secret]\naccessSecretKey = 'access-fixture'\nrefreshSecretKey = 'refresh-fixture'\n"

func TestLoadSecret(t *testing.T) {
	withSecretConfig(t, validSecretConfig)

	params, err := LoadSecret()
	if err != nil || params.AccessSecretKey != "access-fixture" || params.RefreshSecretKey != "refresh-fixture" {
		t.Fatal("valid distinct signing keys rejected")
	}
}

func TestLoadSecretRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{"invalid_toml", "[secret\naccessSecretKey = 'secret-marker'"},
		{"missing_section", ""},
		{"missing_access", "[secret]\nrefreshSecretKey = 'refresh-fixture'"},
		{"missing_refresh", "[secret]\naccessSecretKey = 'access-fixture'"},
		{"empty_access", strings.Replace(validSecretConfig, "access-fixture", "", 1)},
		{"empty_refresh", strings.Replace(validSecretConfig, "refresh-fixture", "", 1)},
		{"whitespace_access", strings.Replace(validSecretConfig, "access-fixture", "  ", 1)},
		{"equal_keys", strings.Replace(validSecretConfig, "refresh-fixture", "access-fixture", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			withSecretConfig(t, test.contents)

			params, err := LoadSecret()
			if err == nil || params != (SecretParams{}) {
				t.Fatal("invalid configuration accepted or returned signing keys")
			}
			for _, value := range []string{"secret-marker", "access-fixture", "refresh-fixture"} {
				if strings.Contains(err.Error(), value) {
					t.Fatal("configuration error disclosed signing material")
				}
			}
		})
	}
}

func TestLoadSecretRejectsMissingFile(t *testing.T) {
	withSecretConfig(t, validSecretConfig)
	if err := os.Remove(filepath.Join("config", "secret.toml")); err != nil {
		t.Fatal("could not remove configuration fixture")
	}

	if _, err := LoadSecret(); err == nil {
		t.Fatal("missing secret file accepted")
	}
}

func withSecretConfig(t *testing.T, contents string) {
	t.Helper()
	withDBConfig(t, validDBConfig)
	if err := os.WriteFile(filepath.Join("config", "secret.toml"), []byte(contents), 0600); err != nil {
		t.Fatal("could not create secret configuration fixture")
	}
}
