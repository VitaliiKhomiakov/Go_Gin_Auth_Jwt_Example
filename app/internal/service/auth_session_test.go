package service

import (
	"context"
	"errors"
	"testing"
)

func TestLockedLoginRechecksCredentials(t *testing.T) {
	for _, change := range []string{"disabled", "password", "deleted"} {
		t.Run(change, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			store.lockFn = func() {
				if change == "disabled" {
					store.user.Enabled = false
				} else {
					store.user.Password = "changed"
				}
			}
			if change == "deleted" {
				store.lockFn = nil
				store.findErr = ErrUserNotFound
			}

			pair, err := auth.SignIn(context.Background(), store.user.Email, "fixture-password")

			if !errors.Is(err, ErrInvalidCredentials) || pair != (TokenPair{}) || store.saved != nil || codec.issuedUser.ID != 0 {
				t.Fatal("changed locked credential issued a session")
			}
		})
	}
}

func TestStoredAccessRequired(t *testing.T) {
	for _, storageFailure := range []bool{false, true} {
		auth, store, _ := authFixture(t)
		store.accessMissing = true
		want := ErrInvalidToken
		if storageFailure {
			want = errors.New("private-query-error")
			store.accessErr = want
		}

		user, err := auth.AuthenticateAccessToken(context.Background(), "fixture-access")

		if user != nil || !errors.Is(err, want) {
			t.Fatal("stored access classification failed")
		}
	}
}

func TestRefreshFailuresReturnNoPair(t *testing.T) {
	for _, failure := range []string{"missing", "lookup", "replace", "stale", "expiry_after_lock", "commit", "classification"} {
		t.Run(failure, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			want := errors.New("private-rotation-error")
			switch failure {
			case "missing":
				store.refreshErr = ErrSessionNotFound
				want = ErrInvalidToken
			case "lookup":
				store.refreshErr = want
			case "replace":
				store.replaceErr = want
			case "stale":
				store.replaceMiss = true
				want = ErrInvalidToken
			case "expiry_after_lock":
				store.lockFn = func() { codec.validateErr = ErrInvalidToken }
				want = ErrInvalidToken
			case "commit":
				store.commitErr = want
			case "classification":
				store.count = 1
				codec.contractErr = want
			}

			pair, err := auth.RefreshSession(context.Background(), "fixture-refresh")

			if pair != (TokenPair{}) || !errors.Is(err, want) || store.transactions != 1 {
				t.Fatal("failed rotation returned a pair or retried")
			}
		})
	}
}

func TestRefreshCleanupDoesNotApplyLoginRetention(t *testing.T) {
	auth, store, _ := authFixture(t)
	store.count = 6

	_, err := auth.RefreshSession(context.Background(), "fixture-refresh")

	if err != nil || len(store.deleted) != 0 || store.saved.ID != 1 {
		t.Fatal("refresh applied login retention or changed age")
	}
}
