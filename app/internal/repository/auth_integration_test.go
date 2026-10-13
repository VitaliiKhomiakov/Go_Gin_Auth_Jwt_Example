//go:build integration

package repository_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"auth/internal/handler"
	"auth/internal/middleware"
	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/route"
	"auth/internal/service"
	"auth/internal/service/config"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var fixtureSequence atomic.Uint64

func authDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Fatal("integration fixture required: set TEST_DATABASE_DSN to an isolated PostgreSQL 15 database")
	}

	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("isolated database connection failed")
	}
	adminPool, err := admin.DB()
	if err != nil {
		t.Fatal("isolated database pool unavailable")
	}
	t.Cleanup(func() {
		if err := adminPool.Close(); err != nil {
			t.Error("fixture admin pool close failed")
		}
	})

	schema := fmt.Sprintf("b42_%d_%d", time.Now().UnixNano(), fixtureSequence.Add(1))
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatal("fixture schema creation failed")
	}
	t.Cleanup(func() {
		if err := admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Error("fixture schema cleanup failed")
		}
	})

	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme != "postgres" {
		t.Fatal("TEST_DATABASE_DSN must be a postgres URL")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	db, err := gorm.Open(postgres.Open(parsed.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("fixture schema connection failed")
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal("fixture schema pool unavailable")
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Error("fixture pool close failed")
		}
	})

	sql, err := os.ReadFile("../../../database/schema.sql")
	if err != nil {
		t.Fatal("fixture schema SQL unavailable")
	}
	if err := db.Exec(string(sql)).Error; err != nil {
		t.Fatal("fixture schema initialization failed")
	}

	return db
}

func realCodec(t *testing.T) *service.JWTCodec {
	t.Helper()
	codec, err := service.NewJWTCodec(config.SecretParams{AccessSecretKey: "integration-access-key", RefreshSecretKey: "integration-refresh-key"})
	if err != nil {
		t.Fatal("fixture codec construction failed")
	}

	return codec
}

func TestSignupDuplicateEmailRace(t *testing.T) {
	db := authDatabase(t)
	auth := service.NewAuth(repository.NewAuthStore(db), realCodec(t))
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := auth.SignUp(context.Background(), service.SignUpInput{Email: "race@example.test", Password: "fixture-password", FirstName: "First", LastName: "Last"})
			results <- err
		}()
	}

	close(start)
	workers.Wait()
	close(results)

	successes, duplicates := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, service.ErrEmailExists) {
			duplicates++
		} else {
			t.Fatal("race returned an unexpected operational failure")
		}
	}
	var count int64
	if err := db.Model(&model.User{}).Where("email = ?", "race@example.test").Count(&count).Error; err != nil {
		t.Fatal("race count failed")
	}
	if successes != 1 || duplicates != 1 || count != 1 {
		t.Fatal("concurrent signup did not yield one user and one duplicate")
	}
}

type fixedCodec struct{}

func (fixedCodec) Issue(user *model.User) (service.TokenPair, error) {
	return service.TokenPair{AccessToken: "rollback-access", RefreshToken: "existing-other-user-refresh"}, nil
}

func (fixedCodec) Validate(string, service.TokenType) (uint, error) {
	return 0, service.ErrInvalidToken
}

func TestTokenIssuanceRollback(t *testing.T) {
	db := authDatabase(t)
	store := repository.NewAuthStore(db)
	auth := service.NewAuth(store, fixedCodec{})
	user, err := auth.SignUp(context.Background(), service.SignUpInput{Email: "rollback@example.test", Password: "fixture-password"})
	if err != nil {
		t.Fatal("rollback user creation failed")
	}
	prior := make([]model.Token, 0, 7)
	for i := 0; i < 6; i++ {
		prior = append(prior, model.Token{UserID: uint64(user.ID), AccessToken: fmt.Sprint("prior-access-", i), RefreshToken: fmt.Sprint("prior-refresh-", i)})
	}
	prior = append(prior, model.Token{UserID: uint64(user.ID) + 100, AccessToken: "other-user-access", RefreshToken: "existing-other-user-refresh"})
	if err := db.Create(&prior).Error; err != nil {
		t.Fatal("prior sessions fixture failed")
	}
	var before []model.Token
	if err := db.Order("id").Find(&before).Error; err != nil {
		t.Fatal("prior sessions read failed")
	}
	deleted := false
	if err := db.Callback().Delete().After("gorm:delete").Register("test:observe_cleanup", func(tx *gorm.DB) {
		if tx.Statement.Table == "token" && tx.Error == nil && tx.RowsAffected == 6 {
			deleted = true
		}
	}); err != nil {
		t.Fatal("cleanup observer registration failed")
	}

	pair, err := auth.SignIn(context.Background(), "rollback@example.test", "fixture-password")

	if err == nil || pair != (service.TokenPair{}) || !deleted {
		t.Fatal("fixture did not fail insertion after actual session cleanup")
	}
	var after []model.Token
	if err := db.Order("id").Find(&after).Error; err != nil {
		t.Fatal("rollback sessions read failed")
	}
	if len(after) != len(before) {
		t.Fatal("cleanup was committed after failed insertion")
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("rollback changed prior session values")
		}
	}
}

func TestAuthRepositoryCancellation(t *testing.T) {
	db := authDatabase(t)
	store := repository.NewAuthStore(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	user := &model.User{Email: "cancelled@example.test", Password: "fixture-hash", Roles: `["STANDARD_USER"]`, Enabled: true}
	checks := []func() error{
		func() error { _, err := store.FindUserByEmail(ctx, user.Email); return err },
		func() error { _, err := store.FindUserByID(ctx, 7); return err },
		func() error { return store.CreateUser(ctx, user) },
		func() error {
			_, err := store.UpdatePasswordIfCurrent(ctx, 7, "current-hash", "replacement-hash")
			return err
		},
		func() error {
			return store.WithSessionTransaction(ctx, func(service.SessionWriter) error { t.Fatal("cancelled transaction invoked callback"); return nil })
		},
	}
	for _, check := range checks {
		if !errors.Is(check(), context.Canceled) {
			t.Fatal("repository lost cancellation")
		}
	}
	for _, operation := range []string{"count", "delete", "save"} {
		err := store.WithSessionTransaction(context.Background(), func(writer service.SessionWriter) error {
			switch operation {
			case "count":
				_, err := writer.CountTokens(ctx, 7)
				return err
			case "delete":
				return writer.DeleteTokens(ctx, 7)
			default:
				return writer.SaveToken(ctx, &model.Token{UserID: 7, AccessToken: "cancelled-access", RefreshToken: "cancelled-refresh"})
			}
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal("transaction writer lost cancellation")
		}
	}
	var count int64
	if err := db.Model(&model.User{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("cancelled user insert persisted data")
	}
	if err := db.Model(&model.Token{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("cancelled token insert persisted data")
	}
}

func TestAuthRepositoryDoesNotLogSecrets(t *testing.T) {
	db := authDatabase(t)
	var output bytes.Buffer
	db.Logger = logger.New(log.New(&output, "", 0), logger.Config{LogLevel: logger.Info})
	store := repository.NewAuthStore(db)
	user := &model.User{Email: "privacy@example.test", Password: "synthetic-private-hash", Roles: `["STANDARD_USER"]`, Enabled: true}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal("privacy fixture creation failed")
	}
	duplicate := *user
	duplicate.ID = 0
	if !errors.Is(store.CreateUser(context.Background(), &duplicate), service.ErrEmailExists) {
		t.Fatal("privacy duplicate did not classify")
	}
	if _, err := store.FindUserByEmail(context.Background(), "private-email@example.test"); !errors.Is(err, service.ErrUserNotFound) {
		t.Fatal("privacy lookup did not classify")
	}
	updated, err := store.UpdatePasswordIfCurrent(context.Background(), user.ID, user.Password, "synthetic-private-replacement-hash")
	if err != nil || !updated {
		t.Fatal("privacy conditional update failed")
	}
	updated, err = store.UpdatePasswordIfCurrent(context.Background(), user.ID, "synthetic-private-replacement-hash", strings.Repeat("private-too-long-hash", 20))
	if err == nil || updated {
		t.Fatal("privacy conditional update did not fail")
	}

	token := &model.Token{UserID: uint64(user.ID), AccessToken: "synthetic-private-access-token", RefreshToken: "synthetic-private-refresh-token"}
	if err := store.WithSessionTransaction(context.Background(), func(writer service.SessionWriter) error { return writer.SaveToken(context.Background(), token) }); err != nil {
		t.Fatal("privacy session creation failed")
	}
	token.ID = 0
	if err := store.WithSessionTransaction(context.Background(), func(writer service.SessionWriter) error { return writer.SaveToken(context.Background(), token) }); err == nil {
		t.Fatal("privacy duplicate session did not fail")
	}

	if output.Len() != 0 {
		t.Fatal("auth repository emitted SQL diagnostics")
	}
}

func TestAuthRouteJourney(t *testing.T) {
	db := authDatabase(t)
	pool, err := db.DB()
	if err != nil {
		t.Fatal("route fixture pool unavailable")
	}
	auth := service.NewAuth(repository.NewAuthStore(db), realCodec(t))
	router := gin.New()
	route.InitRoute(router, handler.NewAuth(auth), middleware.AuthMiddleware(auth), handler.NewHealth(pool.PingContext))
	request := func(method, path, body, token string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()

		router.ServeHTTP(response, req)

		var result map[string]any
		decoder := json.NewDecoder(response.Body)
		if err := decoder.Decode(&result); err != nil {
			t.Fatal("route response was not JSON")
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			t.Fatal("route returned multiple responses")
		}
		return response.Code, result
	}
	status, signup := request("POST", "/auth/signUp", `{"email":"journey@example.test","password":"fixture-password","confirmPassword":"fixture-password","firstName":"First","lastName":"Last","birthday":"2000-02-29","roles":["ADMIN"],"enabled":false}`, "")
	item, ok := signup["item"].(map[string]any)
	if status != 200 || !ok || len(item) != 6 || item["birthday"] != "2000-02-29T00:00:00Z" {
		t.Fatal("route signup failed or changed allowlist")
	}
	id := item["id"]
	var persisted model.User
	if err := db.Where("email = ?", "journey@example.test").First(&persisted).Error; err != nil {
		t.Fatal("registered user read failed")
	}
	var roles []string
	if err := json.Unmarshal([]byte(persisted.Roles), &roles); err != nil || !reflect.DeepEqual(roles, []string{"STANDARD_USER"}) || !persisted.Enabled {
		t.Fatal("privileged signup input changed persisted registration policy")
	}
	valid, upgrade, err := service.VerifyPassword("fixture-password", persisted.Password)
	if err != nil || !valid || upgrade || !strings.HasPrefix(persisted.Password, "$argon2id$") {
		t.Fatal("signup did not persist the accepted password format")
	}
	if float64(persisted.ID) != id {
		t.Fatal("signup identity differs from persisted user")
	}
	status, login := request("POST", "/auth/login", `{"emailOrPhone":"journey@example.test","password":"fixture-password"}`, "")
	if status != 200 || len(login) != 2 {
		t.Fatal("route login failed")
	}
	access, ok := login["accessToken"].(string)
	if !ok {
		t.Fatal("route access missing")
	}
	refresh, ok := login["refreshToken"].(string)
	if !ok {
		t.Fatal("route refresh missing")
	}
	status, identity := request("GET", "/auth/me", "", access)
	if status != 200 || len(identity) != 2 || identity["id"] != id || identity["email"] != "journey@example.test" {
		t.Fatal("login access did not authenticate")
	}
	body, err := json.Marshal(map[string]string{"refreshToken": refresh})
	if err != nil {
		t.Fatal("refresh fixture encoding failed")
	}
	status, refreshed := request("POST", "/auth/refresh", string(body), "")
	if status != 200 || len(refreshed) != 2 {
		t.Fatal("route refresh failed")
	}
	nextAccess, ok := refreshed["accessToken"].(string)
	if !ok {
		t.Fatal("refreshed access missing")
	}
	status, identity = request("GET", "/auth/me", "", nextAccess)
	if status != 200 || identity["id"] != id || len(identity) != 2 {
		t.Fatal("refreshed access did not authenticate")
	}
	var count int64
	if err := db.Model(&model.Token{}).Count(&count).Error; err != nil || count != 2 {
		t.Fatal("route tokens did not persist")
	}
	t.Run("current_enabled_state", func(t *testing.T) {
		var before []model.Token
		if err := db.Order("id").Find(&before).Error; err != nil {
			t.Fatal("issued sessions read failed")
		}
		update := db.Model(&model.User{}).Where("id = ?", persisted.ID).Update("enabled", false)
		if update.Error != nil || update.RowsAffected != 1 {
			t.Fatal("isolated user disable failed")
		}

		status, rejected := request("POST", "/auth/login", `{"emailOrPhone":"journey@example.test","password":"fixture-password"}`, "")
		if status != 401 || !reflect.DeepEqual(rejected, map[string]any{"error": "Incorrect credentials"}) {
			t.Fatal("disabled login did not return generic credentials rejection")
		}
		for _, token := range []string{access, nextAccess} {
			status, rejected = request("GET", "/auth/me", "", token)
			if status != 401 || !reflect.DeepEqual(rejected, map[string]any{"error": "Authentication failed"}) {
				t.Fatal("issued access claims bypassed current disabled state")
			}
		}
		status, rejected = request("POST", "/auth/refresh", string(body), "")
		if status != 401 || !reflect.DeepEqual(rejected, map[string]any{"error": "Authentication failed"}) {
			t.Fatal("issued refresh claims bypassed current disabled state")
		}
		var after []model.Token
		if err := db.Order("id").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("disabled authentication changed stored sessions")
		}

		update = db.Model(&model.User{}).Where("id = ?", persisted.ID).Update("enabled", true)
		if update.Error != nil || update.RowsAffected != 1 {
			t.Fatal("isolated user reenable failed")
		}
		status, identity := request("GET", "/auth/me", "", access)
		if status != 200 || !reflect.DeepEqual(identity, map[string]any{"id": id, "email": "journey@example.test"}) {
			t.Fatal("reenabled user could not authenticate issued access")
		}
		status, login := request("POST", "/auth/login", `{"emailOrPhone":"journey@example.test","password":"fixture-password"}`, "")
		if status != 200 || len(login) != 2 || login["accessToken"] == nil || login["refreshToken"] == nil {
			t.Fatal("reenabled user could not sign in")
		}
		status, refreshed := request("POST", "/auth/refresh", string(body), "")
		if status != 200 || len(refreshed) != 2 || refreshed["accessToken"] == nil || refreshed["refreshToken"] == nil {
			t.Fatal("reenabled user could not refresh issued session")
		}
		if err := db.Model(&model.Token{}).Count(&count).Error; err != nil || count != 4 {
			t.Fatal("reenabled login and refresh did not persist sessions")
		}
	})
	if status, _ := request("GET", "/auth/me", "", refresh); status != 401 {
		t.Fatal("route accepted refresh as access")
	}
	if status, _ := request("GET", "/auth/me", "", ""); status != 401 {
		t.Fatal("me route became public")
	}
	if status, _ := request("POST", "/auth/login", `{"emailOrPhone":"journey@example.test","password":"wrong"}`, ""); status != 401 {
		t.Fatal("wrong password did not return 401")
	}
	if status, _ := request("POST", "/auth/signUp", `{"email":"journey@example.test","password":"fixture-password","confirmPassword":"fixture-password","firstName":"First","lastName":"Last"}`, ""); status != 409 {
		t.Fatal("duplicate signup did not return 409")
	}
	if status, body := request("GET", "/health", "", ""); status != 200 || body["DataBase"] != "OK" {
		t.Fatal("health wiring failed")
	}
	old := httptest.NewRecorder()
	router.ServeHTTP(old, httptest.NewRequest("GET", "/auth/validate", nil))
	if old.Code != 404 {
		t.Fatal("removed validate route remained registered")
	}
}
