//go:build integration

package repository_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"auth/internal/handler"
	"auth/internal/middleware"
	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/route"
	"auth/internal/service"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var sessionPasswordOnce sync.Once
var sessionPassword string
var sessionPasswordErr error

func sessionFixture(t *testing.T) (*gorm.DB, *repository.AuthStore, *service.Auth, model.User) {
	t.Helper()
	sessionPasswordOnce.Do(func() { sessionPassword, sessionPasswordErr = service.HashPassword("fixture-password") })
	if sessionPasswordErr != nil {
		t.Fatal("session password fixture failed")
	}

	db := authDatabase(t)
	store := repository.NewAuthStore(db)
	user := model.User{Email: "session@example.test", Password: sessionPassword, Enabled: true, Roles: `["STANDARD_USER"]`}
	if err := store.CreateUser(context.Background(), &user); err != nil {
		t.Fatal("session user fixture failed")
	}

	return db, store, service.NewAuth(store, realCodec(t)), user
}

func sessionRows(t *testing.T, db *gorm.DB, id uint) []model.Token {
	t.Helper()
	var rows []model.Token
	if err := db.Where("user_id = ?", id).Order("id").Find(&rows).Error; err != nil {
		t.Fatal("session rows read failed")
	}

	return rows
}

func loginSession(t *testing.T, auth *service.Auth, user model.User) service.TokenPair {
	t.Helper()
	pair, err := auth.SignIn(context.Background(), user.Email, "fixture-password")
	if err != nil || pair == (service.TokenPair{}) {
		t.Fatal("fixture login failed")
	}

	return pair
}

func requireAccess(t *testing.T, auth *service.Auth, pair service.TokenPair, allowed bool) {
	t.Helper()
	user, err := auth.AuthenticateAccessToken(context.Background(), pair.AccessToken)
	if allowed {
		if err != nil || user == nil {
			t.Fatal("current access rejected")
		}
	} else if !errors.Is(err, service.ErrInvalidToken) || user != nil {
		t.Fatal("revoked access accepted or misclassified")
	}
}

func requireRefreshRejected(t *testing.T, auth *service.Auth, pair service.TokenPair) {
	t.Helper()
	replacement, err := auth.RefreshSession(context.Background(), pair.RefreshToken)
	if !errors.Is(err, service.ErrInvalidToken) || replacement != (service.TokenPair{}) {
		t.Fatal("revoked refresh accepted or misclassified")
	}
}

func TestSessionRetentionThreshold(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	pairs := make([]service.TokenPair, 0, 6)
	for i := 0; i < 5; i++ {
		pairs = append(pairs, loginSession(t, auth, user))
		if len(sessionRows(t, db, user.ID)) != i+1 {
			t.Fatal("login count incorrect before threshold")
		}
	}
	before := sessionRows(t, db, user.ID)
	if pair, err := auth.SignIn(context.Background(), user.Email, "wrong"); !errors.Is(err, service.ErrInvalidCredentials) || pair != (service.TokenPair{}) {
		t.Fatal("wrong password login succeeded")
	}
	if !reflect.DeepEqual(before, sessionRows(t, db, user.ID)) {
		t.Fatal("failed login changed sessions")
	}

	pairs = append(pairs, loginSession(t, auth, user))

	after := sessionRows(t, db, user.ID)
	if len(after) != 5 || !reflect.DeepEqual(before[1:], after[:4]) {
		t.Fatal("sixth login did not keep newest four")
	}
	requireAccess(t, auth, pairs[0], false)
	requireRefreshRejected(t, auth, pairs[0])
	for _, pair := range pairs[1:] {
		requireAccess(t, auth, pair, true)
	}
	rotated, err := auth.RefreshSession(context.Background(), pairs[1].RefreshToken)
	if err != nil || len(sessionRows(t, db, user.ID)) != 5 {
		t.Fatal("refresh changed session count")
	}
	if sessionRows(t, db, user.ID)[0].ID != after[0].ID {
		t.Fatal("refresh changed session age")
	}

	latest := loginSession(t, auth, user)

	requireAccess(t, auth, rotated, false)
	requireRefreshRejected(t, auth, rotated)
	requireAccess(t, auth, latest, true)
	if len(sessionRows(t, db, user.ID)) != 5 {
		t.Fatal("subsequent login exceeded retention")
	}
}

func TestRefreshRotationReplay(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	old := loginSession(t, auth, user)
	before := sessionRows(t, db, user.ID)

	pair, err := auth.RefreshSession(context.Background(), old.RefreshToken)

	rows := sessionRows(t, db, user.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != before[0].ID || rows[0].UserID != before[0].UserID || pair.AccessToken == old.AccessToken || pair.RefreshToken == old.RefreshToken || rows[0].AccessToken != pair.AccessToken || rows[0].RefreshToken != pair.RefreshToken {
		t.Fatal("rotation did not replace exact pair in original row")
	}
	requireAccess(t, auth, old, false)
	requireRefreshRejected(t, auth, old)
	requireAccess(t, auth, pair, true)
	if _, err := auth.RefreshSession(context.Background(), pair.RefreshToken); err != nil {
		t.Fatal("new refresh rejected")
	}
}

func TestRotationRollback(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	old := loginSession(t, auth, user)
	before := sessionRows(t, db, user.ID)
	if err := db.Exec(`CREATE FUNCTION reject_session_rotation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'rotation fixture rejection'; END $$;
CREATE TRIGGER reject_rotation BEFORE UPDATE ON token FOR EACH ROW EXECUTE FUNCTION reject_session_rotation()`).Error; err != nil {
		t.Fatal("rotation rollback trigger fixture failed")
	}

	pair, err := auth.RefreshSession(context.Background(), old.RefreshToken)

	if err == nil || errors.Is(err, service.ErrInvalidToken) || pair != (service.TokenPair{}) || !reflect.DeepEqual(before, sessionRows(t, db, user.ID)) {
		t.Fatal("definite rotation failure changed old session")
	}
	requireAccess(t, auth, old, true)
	if err := db.Exec(`DROP TRIGGER reject_rotation ON token; DROP FUNCTION reject_session_rotation()`).Error; err != nil {
		t.Fatal("rollback constraint teardown failed")
	}
	if _, err := auth.RefreshSession(context.Background(), old.RefreshToken); err != nil {
		t.Fatal("failed rotation consumed old refresh")
	}
}

func TestSessionUserIsolation(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	other := user
	other.ID = 0
	other.Email = "other@example.test"
	if err := store.CreateUser(context.Background(), &other); err != nil {
		t.Fatal("other user fixture failed")
	}
	otherPair := loginSession(t, auth, other)
	otherRows := sessionRows(t, db, other.ID)
	for i := 0; i < 7; i++ {
		loginSession(t, auth, user)
	}
	if !reflect.DeepEqual(otherRows, sessionRows(t, db, other.ID)) {
		t.Fatal("retention touched another user")
	}
	rows := sessionRows(t, db, user.ID)
	prior := rows[0]
	pair := service.TokenPair{AccessToken: prior.AccessToken, RefreshToken: prior.RefreshToken}
	if _, err := auth.RefreshSession(context.Background(), pair.RefreshToken); err != nil {
		t.Fatal("owner rotation failed")
	}
	if !reflect.DeepEqual(otherRows, sessionRows(t, db, other.ID)) {
		t.Fatal("rotation touched another user")
	}

	err := store.WithSessionTransaction(context.Background(), user.ID, func(_ *model.User, writer service.SessionWriter) error {
		if err := writer.DeleteTokenIDs(context.Background(), []uint{otherRows[0].ID}); err != nil {
			return err
		}
		if _, err := writer.FindRefreshToken(context.Background(), otherPair.RefreshToken); !errors.Is(err, service.ErrSessionNotFound) {
			t.Fatal("writer found other user's refresh")
		}
		if updated, err := writer.ReplaceToken(context.Background(), otherRows[0], pair); err != nil || updated {
			t.Fatal("writer replaced other user's row")
		}
		for _, stale := range []model.Token{prior, {ID: rows[1].ID, AccessToken: "wrong", RefreshToken: rows[1].RefreshToken}, {ID: rows[1].ID, AccessToken: rows[1].AccessToken, RefreshToken: "wrong"}} {
			if updated, err := writer.ReplaceToken(context.Background(), stale, pair); err != nil || updated {
				t.Fatal("conditional rotation accepted stale pair")
			}
		}
		return nil
	})
	if err != nil || !reflect.DeepEqual(otherRows, sessionRows(t, db, other.ID)) {
		t.Fatal("bound writer violated user isolation")
	}
	requireAccess(t, auth, otherPair, true)
}

func TestStoredSessionOwnershipAndAccountState(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	codec := realCodec(t)
	unrecorded, err := codec.Issue(&user)
	if err != nil {
		t.Fatal("unrecorded pair fixture failed")
	}
	requireAccess(t, auth, unrecorded, false)
	requireRefreshRejected(t, auth, unrecorded)
	wrongOwner := model.Token{UserID: uint64(user.ID + 100), AccessToken: unrecorded.AccessToken, RefreshToken: unrecorded.RefreshToken}
	if err := db.Create(&wrongOwner).Error; err != nil {
		t.Fatal("wrong owner fixture failed")
	}
	requireAccess(t, auth, unrecorded, false)
	requireRefreshRejected(t, auth, unrecorded)
	pair := loginSession(t, auth, user)
	if err := db.Where("user_id = ?", user.ID).Delete(&model.Token{}).Error; err != nil {
		t.Fatal("session deletion failed")
	}
	requireAccess(t, auth, pair, false)
	requireRefreshRejected(t, auth, pair)
	pair = loginSession(t, auth, user)
	before := sessionRows(t, db, user.ID)
	if err := db.Model(&model.User{}).Where("id = ?", user.ID).Update("enabled", false).Error; err != nil {
		t.Fatal("account disable failed")
	}
	requireAccess(t, auth, pair, false)
	requireRefreshRejected(t, auth, pair)
	if !reflect.DeepEqual(before, sessionRows(t, db, user.ID)) {
		t.Fatal("disabled request changed sessions")
	}
	if err := db.Where("id = ?", user.ID).Delete(&model.User{}).Error; err != nil {
		t.Fatal("account deletion failed")
	}
	requireAccess(t, auth, pair, false)
	requireRefreshRejected(t, auth, pair)
	if err := store.WithSessionTransaction(context.Background(), user.ID, func(*model.User, service.SessionWriter) error {
		t.Fatal("missing locked user reached callback")
		return nil
	}); !errors.Is(err, service.ErrUserNotFound) {
		t.Fatal("missing locked user misclassified")
	}
}

type sessionFixtureClaims struct {
	UserID    uint              `json:"userID"`
	ExpiresAt int64             `json:"exp"`
	TokenType service.TokenType `json:"tokenType"`
	ID        string            `json:"jti"`
}

func (sessionFixtureClaims) Valid() error { return nil }

func signedSession(t *testing.T, userID uint, accessExpiry, refreshExpiry int64, id string) service.TokenPair {
	t.Helper()
	var pair service.TokenPair
	for _, spec := range []struct {
		purpose service.TokenType
		expiry  int64
		key     string
		target  *string
	}{
		{service.AccessToken, accessExpiry, "integration-access-key", &pair.AccessToken},
		{service.RefreshToken, refreshExpiry, "integration-refresh-key", &pair.RefreshToken},
	} {
		claims := sessionFixtureClaims{UserID: userID, ExpiresAt: spec.expiry, TokenType: spec.purpose, ID: id}
		value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(spec.key))
		if err != nil {
			t.Fatal("signed session fixture failed")
		}
		*spec.target = value
	}

	return pair
}

func TestSessionLegacyCleanupPagination(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	rows := make([]model.Token, 0, 207)
	for i := 0; i < 205; i++ {
		pair := service.TokenPair{AccessToken: fmt.Sprint("legacy-access-", i), RefreshToken: fmt.Sprint("legacy-refresh-", i)}
		if i%40 == 0 {
			pair = signedSession(t, user.ID, time.Now().Add(time.Hour).Unix(), time.Now().Add(time.Hour).Unix(), fmt.Sprint("paged-current-", i))
		}
		rows = append(rows, model.Token{UserID: uint64(user.ID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken})
	}
	expiredAccess := signedSession(t, user.ID, time.Now().Add(-time.Hour).Unix(), time.Now().Add(time.Hour).Unix(), "expired-access-current")
	rows = append(rows, model.Token{UserID: uint64(user.ID), AccessToken: expiredAccess.AccessToken, RefreshToken: expiredAccess.RefreshToken})
	wrongOwner := signedSession(t, user.ID+100, time.Now().Add(time.Hour).Unix(), time.Now().Add(time.Hour).Unix(), "wrong-owner")
	rows = append(rows, model.Token{UserID: uint64(user.ID), AccessToken: wrongOwner.AccessToken, RefreshToken: wrongOwner.RefreshToken})
	if err := db.Create(&rows).Error; err != nil {
		t.Fatal("paged legacy fixture failed")
	}

	pair := loginSession(t, auth, user)

	after := sessionRows(t, db, user.ID)
	if len(after) != 5 || !reflect.DeepEqual(after[:4], []model.Token{rows[120], rows[160], rows[200], rows[205]}) {
		t.Fatal("paged cleanup removed current expired access or retained legacy")
	}
	for _, index := range []int{0, 40, 80} {
		retired := service.TokenPair{AccessToken: rows[index].AccessToken, RefreshToken: rows[index].RefreshToken}
		requireAccess(t, auth, retired, false)
		requireRefreshRejected(t, auth, retired)
	}
	requireAccess(t, auth, expiredAccess, false)
	requireAccess(t, auth, pair, true)
	if _, err := auth.RefreshSession(context.Background(), expiredAccess.RefreshToken); err != nil {
		t.Fatal("expired access incorrectly retired current refresh")
	}
}

func TestSessionDatabaseErrorsHTTP(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	pair := loginSession(t, auth, user)
	pool, err := db.DB()
	if err != nil {
		t.Fatal("error fixture pool unavailable")
	}
	router := gin.New()
	route.InitRoute(router, handler.NewAuth(auth), middleware.AuthMiddleware(auth), handler.NewHealth(pool.PingContext))
	if err := db.Exec(`DROP TABLE token`).Error; err != nil {
		t.Fatal("session outage fixture failed")
	}
	for _, spec := range []struct{ method, path, body, token string }{
		{"GET", "/auth/me", "", pair.AccessToken},
		{"POST", "/auth/refresh", `{"refreshToken":"` + pair.RefreshToken + `"}`, ""},
		{"POST", "/auth/login", `{"emailOrPhone":"session@example.test","password":"fixture-password"}`, ""},
	} {
		req := httptest.NewRequest(spec.method, spec.path, strings.NewReader(spec.body))
		req.Header.Set("Content-Type", "application/json")
		if spec.token != "" {
			req.Header.Set("Authorization", "Bearer "+spec.token)
		}
		response := httptest.NewRecorder()

		router.ServeHTTP(response, req)

		if response.Code != 500 || response.Body.String() != "{\"error\":\"Internal server error\"}" {
			t.Fatal("session SQL failure returned unsafe or misleading HTTP response")
		}
	}
}

func TestRefreshLegacyCleanupPreservesCurrentRows(t *testing.T) {
	db, _, auth, user := sessionFixture(t)
	codec := realCodec(t)
	current := make([]model.Token, 0, 6)
	for i := 0; i < 6; i++ {
		pair, err := codec.Issue(&user)
		if err != nil {
			t.Fatal("refresh cleanup fixture signing failed")
		}
		current = append(current, model.Token{UserID: uint64(user.ID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken})
	}
	if err := db.Create(&current).Error; err != nil {
		t.Fatal("refresh cleanup current fixture failed")
	}
	legacy := []model.Token{
		{UserID: uint64(user.ID), AccessToken: "obsolete-access", RefreshToken: "obsolete-refresh"},
		{UserID: uint64(user.ID + 100), AccessToken: "other-obsolete-access", RefreshToken: "other-obsolete-refresh"},
	}
	if err := db.Create(&legacy).Error; err != nil {
		t.Fatal("refresh cleanup obsolete fixture failed")
	}
	old := service.TokenPair{AccessToken: current[0].AccessToken, RefreshToken: current[0].RefreshToken}

	pair, err := auth.RefreshSession(context.Background(), old.RefreshToken)

	rows := sessionRows(t, db, user.ID)
	if err != nil || len(rows) != 6 || rows[0].ID != current[0].ID || !reflect.DeepEqual(rows[1:], current[1:]) {
		t.Fatal("refresh cleanup applied login retention or changed current sessions")
	}
	if other := sessionRows(t, db, user.ID+100); len(other) != 1 || other[0] != legacy[1] {
		t.Fatal("refresh cleanup touched another user")
	}
	requireAccess(t, auth, old, false)
	requireRefreshRejected(t, auth, old)
	requireAccess(t, auth, pair, true)
	for _, row := range rows[1:] {
		requireAccess(t, auth, service.TokenPair{AccessToken: row.AccessToken, RefreshToken: row.RefreshToken}, true)
	}
}
