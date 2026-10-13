package service

import (
	"context"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"

	"auth/internal/model"
)

func TestLegacyPasswordUpgrade(t *testing.T) {
	auth, store, _ := authFixture(t)
	legacy := legacyPassword("fixture-password")
	store.user.Password = legacy
	ctx := context.WithValue(context.Background(), struct{}{}, "migration")

	pair, err := auth.SignIn(ctx, store.user.Email, "wrong-password")

	if !errors.Is(err, ErrInvalidCredentials) || pair != (TokenPair{}) || store.updates != 0 || store.transactions != 0 || store.user.Password != legacy {
		t.Fatal("wrong legacy password wrote data or issued a session")
	}
	store.trace = nil

	pair, err = auth.SignIn(ctx, store.user.Email, "fixture-password")

	want := []string{"find_email", "update_password", "sign", "begin", "count", "save", "commit"}
	if err != nil || pair == (TokenPair{}) || store.updates != 1 || !strings.HasPrefix(store.user.Password, passwordPrefix) || !reflect.DeepEqual(store.trace, want) {
		t.Fatal("first legacy login did not upgrade before issuing")
	}
	upgraded := store.user.Password
	store.trace = nil

	pair, err = auth.SignIn(ctx, store.user.Email, "fixture-password")

	if err != nil || pair == (TokenPair{}) || store.updates != 1 || store.user.Password != upgraded || !reflect.DeepEqual(store.trace, []string{"find_email", "sign", "begin", "count", "save", "commit"}) {
		t.Fatal("subsequent login rewrote the upgraded credential")
	}
	for _, actual := range store.contexts {
		if actual != ctx {
			t.Fatal("upgrade replaced request context")
		}
	}
}

func TestPasswordUpgradeFailure(t *testing.T) {
	replacement, err := HashPassword("changed-password")
	if err != nil {
		t.Fatal("replacement fixture failed")
	}
	for _, name := range []string{"update_error", "winner_success", "winner_changed", "winner_disabled", "winner_deleted", "winner_malformed", "winner_legacy", "reload_error"} {
		t.Run(name, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			upgraded := store.user.Password
			legacy := legacyPassword("fixture-password")
			store.user.Password = legacy
			failure := errors.New("private-upgrade-failure")
			want := failure
			store.updateFn = func(ctx context.Context, id uint, current, candidate string) (bool, error) {
				if id != 7 || current != legacy || !strings.HasPrefix(candidate, passwordPrefix) || store.transactions != 0 {
					t.Fatal("conditional update contract or transaction order changed")
				}
				if name == "update_error" {
					return false, failure
				}
				store.user.Password = upgraded
				store.user.Email = "current@example.test"
				switch name {
				case "winner_changed":
					store.user.Password = replacement
					want = ErrInvalidCredentials
				case "winner_disabled":
					store.user.Enabled = false
					want = ErrInvalidCredentials
				case "winner_deleted":
					store.findErr = ErrUserNotFound
					want = ErrInvalidCredentials
				case "winner_malformed":
					store.user.Password = "invalid-stored-encoding"
					want = errPasswordEncoding
				case "winner_legacy":
					store.user.Password = legacy
					want = nil
				case "reload_error":
					store.findErr = failure
				}
				return false, nil
			}

			pair, err := auth.SignIn(context.Background(), "fixture@example.test", "fixture-password")

			if store.updates != 1 {
				t.Fatal("upgrade retried conditional update")
			}
			if name == "winner_success" {
				if err != nil || pair == (TokenPair{}) || store.transactions != 1 || codec.issuedUser.Email != "current@example.test" || codec.issuedUser.Password != upgraded || store.user.Password != upgraded {
					t.Fatal("loser did not use reverified current winner identity")
				}
				return
			}
			if err == nil || (want != nil && !errors.Is(err, want)) || pair != (TokenPair{}) || store.transactions != 0 || store.saved != nil || codec.issuedUser != (model.User{}) {
				t.Fatal("failed upgrade returned credentials, issued tokens or wrote session")
			}
			if name == "winner_changed" && store.user.Password != replacement {
				t.Fatal("loser overwrote a changed password")
			}
		})
	}
}

func TestPasswordRandomFailureStopsOperations(t *testing.T) {
	auth, store, codec := authFixture(t)
	store.user.Password = legacyPassword("fixture-password")
	original := rand.Reader
	rand.Reader = failingRandom{}
	t.Cleanup(func() { rand.Reader = original })

	pair, err := auth.SignIn(context.Background(), store.user.Email, "fixture-password")

	if err == nil || pair != (TokenPair{}) || store.updates != 0 || store.transactions != 0 || codec.issuedUser != (model.User{}) {
		t.Fatal("failed upgrade salt generation reached persistence or issuance")
	}

	user, err := auth.SignUp(context.Background(), SignUpInput{Email: "new@example.test", Password: "fixture-password"})

	if err == nil || user != (UserWithoutSecret{}) || store.created != nil {
		t.Fatal("failed signup salt generation persisted user")
	}
}
