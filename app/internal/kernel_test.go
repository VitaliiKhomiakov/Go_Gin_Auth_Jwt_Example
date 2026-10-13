package internal

import (
	"os"
	"path/filepath"
	"testing"

	"auth/internal/system/database"

	"github.com/gin-gonic/gin"
)

func TestInitRejectsInvalidSigningKeysBeforeDatabase(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal("working directory unavailable")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "config"), 0700); err != nil {
		t.Fatal("fixture directory unavailable")
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal("fixture directory unavailable")
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error("could not restore working directory")
		}
	})
	previous := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = previous })

	for _, test := range []struct {
		contents     string
		errorMessage string
	}{
		{"", "token configuration requires nonempty signing keys"},
		{"[secret]\naccessSecretKey = 'same'\nrefreshSecretKey = 'same'", "token configuration requires distinct signing keys"},
	} {
		if err := os.WriteFile(filepath.Join("config", "secret.toml"), []byte(test.contents), 0600); err != nil {
			t.Fatal("fixture configuration unavailable")
		}
		router := gin.New()

		if err := Init(router); err == nil || err.Error() != test.errorMessage || database.DB != nil || len(router.Routes()) != 0 {
			t.Fatal("invalid signing keys did not prevent startup before database initialization")
		}
	}
}
