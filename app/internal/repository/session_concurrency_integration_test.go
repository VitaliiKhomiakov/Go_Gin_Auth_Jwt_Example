//go:build integration

package repository_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/service"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type sessionBarrierStore struct {
	*repository.AuthStore
	arrived chan struct{}
	release chan struct{}
}

func (s *sessionBarrierStore) WithSessionTransaction(ctx context.Context, id uint, operation func(*model.User, service.SessionWriter) error) error {
	select {
	case s.arrived <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return s.AuthStore.WithSessionTransaction(ctx, id, operation)
}

type sessionResult struct {
	pair service.TokenPair
	err  error
}

func concurrentSessions(t *testing.T, db *gorm.DB, store *repository.AuthStore, userID uint, operations []func(context.Context, *service.Auth) (service.TokenPair, error)) []sessionResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	locked := holdSessionUser(t, db, userID)
	barrier := &sessionBarrierStore{AuthStore: store, arrived: make(chan struct{}, len(operations)), release: make(chan struct{})}
	auth := service.NewAuth(barrier, realCodec(t))
	results := make(chan sessionResult, len(operations))
	for _, operation := range operations {
		go func(operation func(context.Context, *service.Auth) (service.TokenPair, error)) {
			pair, err := operation(ctx, auth)
			results <- sessionResult{pair, err}
		}(operation)
	}
	for range operations {
		select {
		case <-barrier.arrived:
		case <-ctx.Done():
			t.Fatal("session operations did not reach transaction barrier")
		}
	}

	close(barrier.release)
	waitSessionLocks(t, db, locked, len(operations))
	if err := locked.Commit().Error; err != nil {
		t.Fatal("concurrent user lock fixture commit failed")
	}

	collected := make([]sessionResult, 0, len(operations))
	for range operations {
		select {
		case result := <-results:
			collected = append(collected, result)
		case <-ctx.Done():
			t.Fatal("concurrent session operations did not finish")
		}
	}

	return collected
}

func TestRefreshRaceSingleWinner(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	old := loginSession(t, auth, user)
	before := sessionRows(t, db, user.ID)
	refresh := func(ctx context.Context, auth *service.Auth) (service.TokenPair, error) {
		return auth.RefreshSession(ctx, old.RefreshToken)
	}

	results := concurrentSessions(t, db, store, user.ID, []func(context.Context, *service.Auth) (service.TokenPair, error){refresh, refresh})

	wins, losses := 0, 0
	var winner service.TokenPair
	for _, result := range results {
		if result.err == nil && result.pair != (service.TokenPair{}) {
			wins++
			winner = result.pair
		} else if errors.Is(result.err, service.ErrInvalidToken) && result.pair == (service.TokenPair{}) {
			losses++
		} else {
			t.Fatal("refresh race returned unexpected result")
		}
	}
	rows := sessionRows(t, db, user.ID)
	if wins != 1 || losses != 1 || len(rows) != 1 || rows[0].ID != before[0].ID || rows[0].AccessToken != winner.AccessToken || rows[0].RefreshToken != winner.RefreshToken {
		t.Fatal("refresh race did not establish exactly one persisted winner")
	}
	requireAccess(t, auth, old, false)
	requireRefreshRejected(t, auth, old)
	requireAccess(t, auth, winner, true)
	if _, err := auth.RefreshSession(context.Background(), winner.RefreshToken); err != nil {
		t.Fatal("race winner refresh invalid")
	}
}

func TestConcurrentThresholdLogins(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	pairs := make([]service.TokenPair, 0, 5)
	for i := 0; i < 5; i++ {
		pairs = append(pairs, loginSession(t, auth, user))
	}
	before := sessionRows(t, db, user.ID)
	login := func(ctx context.Context, auth *service.Auth) (service.TokenPair, error) {
		return auth.SignIn(ctx, user.Email, "fixture-password")
	}

	results := concurrentSessions(t, db, store, user.ID, []func(context.Context, *service.Auth) (service.TokenPair, error){login, login})

	rows := sessionRows(t, db, user.ID)
	if len(rows) != 5 || !reflect.DeepEqual(before[2:], rows[:3]) {
		t.Fatal("concurrent logins exceeded cap or removed newer rows")
	}
	for _, result := range results {
		if result.err != nil {
			t.Fatal("valid concurrent login failed")
		}
		requireAccess(t, auth, result.pair, true)
	}
	for _, pair := range pairs[:2] {
		requireAccess(t, auth, pair, false)
		requireRefreshRejected(t, auth, pair)
	}
	for _, pair := range pairs[2:] {
		requireAccess(t, auth, pair, true)
	}
}

func TestLoginRefreshContention(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	pairs := make([]service.TokenPair, 0, 5)
	for i := 0; i < 5; i++ {
		pairs = append(pairs, loginSession(t, auth, user))
	}
	before := sessionRows(t, db, user.ID)
	login := func(ctx context.Context, auth *service.Auth) (service.TokenPair, error) {
		return auth.SignIn(ctx, user.Email, "fixture-password")
	}
	refresh := func(ctx context.Context, auth *service.Auth) (service.TokenPair, error) {
		return auth.RefreshSession(ctx, pairs[4].RefreshToken)
	}

	results := concurrentSessions(t, db, store, user.ID, []func(context.Context, *service.Auth) (service.TokenPair, error){login, refresh})

	rows := sessionRows(t, db, user.ID)
	if len(rows) != 5 || rows[3].ID != before[4].ID {
		t.Fatal("contention lost original rotation row or violated cap")
	}
	for _, result := range results {
		if result.err != nil {
			t.Fatal("unretired concurrent session failed")
		}
		requireAccess(t, auth, result.pair, true)
	}
	requireAccess(t, auth, pairs[0], false)
	requireRefreshRejected(t, auth, pairs[0])
	requireAccess(t, auth, pairs[4], false)
	requireRefreshRejected(t, auth, pairs[4])
}

func holdSessionUser(t *testing.T, db *gorm.DB, userID uint) *gorm.DB {
	t.Helper()
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal("user lock fixture transaction failed")
	}
	t.Cleanup(func() { tx.Rollback() })
	var user model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, userID).Error; err != nil {
		t.Fatal("fixture user lock failed")
	}

	return tx
}

func waitSessionLocks(t *testing.T, db, holder *gorm.DB, count int) {
	t.Helper()
	var pid int
	if err := holder.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
		t.Fatal("fixture lock owner lookup failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		var blocked int
		if err := db.WithContext(ctx).Raw("WITH RECURSIVE blocked AS (SELECT pid FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid)) UNION SELECT activity.pid FROM pg_stat_activity activity JOIN blocked ON blocked.pid = ANY(pg_blocking_pids(activity.pid))) SELECT count(*) FROM blocked", pid).Scan(&blocked).Error; err != nil {
			t.Fatal("session writers did not block on the locked user")
		}
		if blocked >= count {
			return
		}
	}
}

func TestSessionLockWaitCancellation(t *testing.T) {
	db, store, auth, user := sessionFixture(t)
	pair := loginSession(t, auth, user)
	before := sessionRows(t, db, user.ID)
	tx := holdSessionUser(t, db, user.ID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	barrier := &sessionBarrierStore{AuthStore: store, arrived: make(chan struct{}, 1)}
	waiting := service.NewAuth(barrier, realCodec(t))
	result := make(chan sessionResult, 1)
	go func() {
		pair, err := waiting.RefreshSession(ctx, pair.RefreshToken)
		result <- sessionResult{pair, err}
	}()
	select {
	case <-barrier.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("refresh did not reach lock")
	}

	waitSessionLocks(t, db, tx, 1)
	cancel()

	select {
	case result := <-result:
		if result.err == nil || errors.Is(result.err, service.ErrInvalidToken) || result.pair != (service.TokenPair{}) {
			t.Fatal("cancelled lock wait became success or invalid token")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled lock wait did not finish")
	}
	tx.Rollback()
	if !reflect.DeepEqual(before, sessionRows(t, db, user.ID)) {
		t.Fatal("cancelled lock wait changed session")
	}
	requireAccess(t, auth, pair, true)
	if _, err := auth.RefreshSession(context.Background(), pair.RefreshToken); err != nil {
		t.Fatal("cancellation consumed refresh")
	}
}

func TestRefreshExpiryAfterLockWait(t *testing.T) {
	db, store, _, user := sessionFixture(t)
	expiry := time.Now().Add(2 * time.Second).Unix()
	pair := signedSession(t, user.ID, time.Now().Add(time.Hour).Unix(), expiry, "expiry-after-wait")
	row := model.Token{UserID: uint64(user.ID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal("expiry session fixture failed")
	}
	tx := holdSessionUser(t, db, user.ID)
	barrier := &sessionBarrierStore{AuthStore: store, arrived: make(chan struct{}, 1)}
	auth := service.NewAuth(barrier, realCodec(t))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan sessionResult, 1)
	go func() { pair, err := auth.RefreshSession(ctx, pair.RefreshToken); result <- sessionResult{pair, err} }()
	select {
	case <-barrier.arrived:
	case <-ctx.Done():
		t.Fatal("refresh expired before reaching lock fixture")
	}
	waitSessionLocks(t, db, tx, 1)
	deadline := time.NewTimer(time.Until(time.Unix(expiry, 0)))
	defer deadline.Stop()
	<-deadline.C

	if err := tx.Commit().Error; err != nil {
		t.Fatal("expiry lock fixture release failed")
	}

	select {
	case result := <-result:
		if !errors.Is(result.err, service.ErrInvalidToken) || result.pair != (service.TokenPair{}) {
			t.Fatal("refresh skipped strict expiry after lock wait")
		}
	case <-ctx.Done():
		t.Fatal("expiry wait did not finish")
	}
	rows := sessionRows(t, db, user.ID)
	if len(rows) != 1 || rows[0] != row {
		t.Fatal("expired waiting refresh changed session")
	}
}

func TestLoginCredentialChangeAfterLockWait(t *testing.T) {
	for _, change := range []string{"password", "disabled", "deleted"} {
		t.Run(change, func(t *testing.T) {
			db, store, auth, user := sessionFixture(t)
			pair := loginSession(t, auth, user)
			before := sessionRows(t, db, user.ID)
			tx := holdSessionUser(t, db, user.ID)
			barrier := &sessionBarrierStore{AuthStore: store, arrived: make(chan struct{}, 1)}
			waiting := service.NewAuth(barrier, realCodec(t))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result := make(chan sessionResult, 1)
			go func() {
				pair, err := waiting.SignIn(ctx, user.Email, "fixture-password")
				result <- sessionResult{pair, err}
			}()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal("login did not verify before transaction")
			}
			waitSessionLocks(t, db, tx, 1)
			switch change {
			case "password":
				if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Update("password", legacyFixturePassword("changed-password")).Error; err != nil {
					t.Fatal("locked password change failed")
				}
			case "disabled":
				if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Update("enabled", false).Error; err != nil {
					t.Fatal("locked disable failed")
				}
			case "deleted":
				if err := tx.Where("id = ?", user.ID).Delete(&model.User{}).Error; err != nil {
					t.Fatal("locked deletion failed")
				}
			}

			if err := tx.Commit().Error; err != nil {
				t.Fatal("credential fixture commit failed")
			}

			select {
			case result := <-result:
				if !errors.Is(result.err, service.ErrInvalidCredentials) || result.pair != (service.TokenPair{}) {
					t.Fatal("changed locked credential issued session")
				}
			case <-ctx.Done():
				t.Fatal("credential wait did not finish")
			}
			if !reflect.DeepEqual(before, sessionRows(t, db, user.ID)) {
				t.Fatal("changed credential modified existing session")
			}
			if change == "password" {
				requireAccess(t, auth, pair, true)
			} else {
				requireAccess(t, auth, pair, false)
			}
		})
	}
}
