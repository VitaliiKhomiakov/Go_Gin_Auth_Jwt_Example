//go:build integration

package repository_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/service"
)

func legacyFixturePassword(password string) string {
	sum := sha256.Sum256([]byte(password + "your_salt"))
	return hex.EncodeToString(sum[:])
}

func TestPasswordConditionalUpdate(t *testing.T) {
	db := authDatabase(t)
	store := repository.NewAuthStore(db)
	user := model.User{Email: "cas@example.test", Password: legacyFixturePassword("fixture-password"), Roles: `["STANDARD_USER"]`, Enabled: true, FirstName: "Preserved", LastLogin: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	if err := store.CreateUser(context.Background(), &user); err != nil {
		t.Fatal("CAS fixture creation failed")
	}
	before, err := store.FindUserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal("CAS fixture read failed")
	}
	encoded, err := service.HashPassword("fixture-password")
	if err != nil {
		t.Fatal("CAS fixture hash failed")
	}

	for _, test := range []struct {
		id      uint
		current string
	}{
		{user.ID + 1, user.Password}, {user.ID, "different-current-hash"},
	} {
		updated, err := store.UpdatePasswordIfCurrent(context.Background(), test.id, test.current, encoded)

		if err != nil || updated {
			t.Fatal("CAS changed absent user or mismatched credential")
		}
	}
	updated, err := store.UpdatePasswordIfCurrent(context.Background(), user.ID, user.Password, strings.Repeat("x", 256))
	if err == nil || updated {
		t.Fatal("CAS failed to report database rejection")
	}

	updated, err = store.UpdatePasswordIfCurrent(context.Background(), user.ID, user.Password, encoded)

	if err != nil || !updated {
		t.Fatal("matching CAS did not replace credential")
	}
	updated, err = store.UpdatePasswordIfCurrent(context.Background(), user.ID, user.Password, "stale-replacement")
	if err != nil || updated {
		t.Fatal("stale CAS overwrote upgraded credential")
	}
	after, err := store.FindUserByID(context.Background(), user.ID)
	if err != nil || after.Password != encoded {
		t.Fatal("CAS stored an unexpected credential")
	}
	before.Password, after.Password = "", ""
	if !reflect.DeepEqual(before, after) {
		t.Fatal("password-only CAS changed unrelated user fields")
	}
}

type synchronizedPasswordStore struct {
	service.AuthStore
	read                     chan struct{}
	release                  chan struct{}
	mutex                    sync.Mutex
	winners, losses, reloads int
	winner                   string
}

func (s *synchronizedPasswordStore) FindUserByEmail(ctx context.Context, email string) (model.User, error) {
	user, err := s.AuthStore.FindUserByEmail(ctx, email)
	if err != nil {
		return model.User{}, err
	}
	select {
	case s.read <- struct{}{}:
	case <-ctx.Done():
		return model.User{}, ctx.Err()
	}
	select {
	case <-s.release:
		return user, nil
	case <-ctx.Done():
		return model.User{}, ctx.Err()
	}
}

func (s *synchronizedPasswordStore) UpdatePasswordIfCurrent(ctx context.Context, id uint, current, candidate string) (bool, error) {
	updated, err := s.AuthStore.UpdatePasswordIfCurrent(ctx, id, current, candidate)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err == nil {
		if updated {
			s.winners++
			s.winner = candidate
		} else {
			s.losses++
		}
	}
	return updated, err
}

func (s *synchronizedPasswordStore) FindUserByID(ctx context.Context, id uint) (*model.User, error) {
	s.mutex.Lock()
	s.reloads++
	s.mutex.Unlock()
	return s.AuthStore.FindUserByID(ctx, id)
}

func TestConcurrentPasswordUpgrade(t *testing.T) {
	db := authDatabase(t)
	realStore := repository.NewAuthStore(db)
	user := model.User{Email: "concurrent-upgrade@example.test", Password: legacyFixturePassword("fixture-password"), Roles: `["STANDARD_USER"]`, Enabled: true}
	if err := realStore.CreateUser(context.Background(), &user); err != nil {
		t.Fatal("concurrent fixture creation failed")
	}
	store := &synchronizedPasswordStore{AuthStore: realStore, read: make(chan struct{}, 2), release: make(chan struct{})}
	auth := service.NewAuth(store, realCodec(t))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type result struct {
		pair service.TokenPair
		err  error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			pair, err := auth.SignIn(ctx, user.Email, "fixture-password")
			results <- result{pair, err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-store.read:
		case <-ctx.Done():
			t.Fatal("concurrent legacy reads did not reach barrier")
		}
	}

	close(store.release)

	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err != nil || result.pair == (service.TokenPair{}) {
				t.Fatal("concurrent valid legacy login failed")
			}
		case <-ctx.Done():
			t.Fatal("concurrent password upgrades did not finish")
		}
	}
	store.mutex.Lock()
	winners, losses, reloads, winner := store.winners, store.losses, store.reloads, store.winner
	store.mutex.Unlock()
	if winners != 1 || losses != 1 || reloads != 1 {
		t.Fatal("race did not establish one CAS winner and a reverified loser")
	}
	current, err := realStore.FindUserByID(context.Background(), user.ID)
	if err != nil || current.Password != winner || current.Password == user.Password {
		t.Fatal("concurrent loser overwrote winner or legacy remained")
	}
	valid, upgrade, err := service.VerifyPassword("fixture-password", current.Password)
	if err != nil || !valid || upgrade {
		t.Fatal("race stored an invalid or legacy credential")
	}
	var count int64
	if err := db.Model(&model.Token{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil || count != 2 {
		t.Fatal("concurrent upgrade did not persist both allowed sessions")
	}
}

func TestPasswordUpgradeDatabaseFailure(t *testing.T) {
	db := authDatabase(t)
	store := repository.NewAuthStore(db)
	user := model.User{Email: "upgrade-failure@example.test", Password: legacyFixturePassword("fixture-password"), Roles: `["STANDARD_USER"]`, Enabled: true}
	if err := store.CreateUser(context.Background(), &user); err != nil {
		t.Fatal("upgrade failure fixture creation failed")
	}
	if err := db.Exec(`ALTER TABLE "user" ADD CONSTRAINT reject_password_upgrade CHECK (length(password) = 64)`).Error; err != nil {
		t.Fatal("upgrade rejection constraint failed")
	}
	auth := service.NewAuth(store, realCodec(t))

	pair, err := auth.SignIn(context.Background(), user.Email, "fixture-password")

	if err == nil || errors.Is(err, service.ErrInvalidCredentials) || pair != (service.TokenPair{}) {
		t.Fatal("database upgrade failure became credentials rejection or success")
	}
	current, err := store.FindUserByID(context.Background(), user.ID)
	if err != nil || current.Password != user.Password {
		t.Fatal("failed migration changed credential")
	}
	var count int64
	if err := db.Model(&model.Token{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed migration persisted a session")
	}
}
