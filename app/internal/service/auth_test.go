package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"auth/internal/model"
)

type authStoreFake struct {
	user                                                        model.User
	findErr, createErr, countErr, deleteErr, saveErr, commitErr error
	count                                                       int64
	contexts                                                    []context.Context
	trace                                                       []string
	created                                                     *model.User
	saved                                                       *model.Token
	transactions                                                int
}

func (f *authStoreFake) FindUserByEmail(ctx context.Context, email string) (model.User, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "find_email")
	return f.user, f.findErr
}

func (f *authStoreFake) FindUserByID(ctx context.Context, id uint) (*model.User, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "find_id")
	return &f.user, f.findErr
}

func (f *authStoreFake) CreateUser(ctx context.Context, user *model.User) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "create")
	f.created = user
	user.ID = 7
	return f.createErr
}

func (f *authStoreFake) WithSessionTransaction(ctx context.Context, operation func(SessionWriter) error) error {
	f.contexts = append(f.contexts, ctx)
	f.transactions++
	f.trace = append(f.trace, "begin")
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := operation(f); err != nil {
		return err
	}
	f.trace = append(f.trace, "commit")
	return f.commitErr
}

func (f *authStoreFake) CountTokens(ctx context.Context, id uint) (int64, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "count")
	return f.count, f.countErr
}

func (f *authStoreFake) DeleteTokens(ctx context.Context, id uint) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "delete")
	return f.deleteErr
}

func (f *authStoreFake) SaveToken(ctx context.Context, token *model.Token) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "save")
	f.saved = token
	return f.saveErr
}

type tokenCodecFake struct {
	store                 *authStoreFake
	issueErr, validateErr error
	purposes              []TokenType
}

func (f *tokenCodecFake) Issue(user *model.User) (TokenPair, error) {
	f.store.trace = append(f.store.trace, "sign")
	return TokenPair{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh"}, f.issueErr
}

func (f *tokenCodecFake) Validate(token string, purpose TokenType) (uint, error) {
	f.purposes = append(f.purposes, purpose)
	f.store.trace = append(f.store.trace, "validate")
	return 7, f.validateErr
}

func authFixture(t *testing.T) (*Auth, *authStoreFake, *tokenCodecFake) {
	t.Helper()
	password, err := hashPassword("fixture-password", "your_salt")
	if err != nil {
		t.Fatal("fixture hash failed")
	}
	store := &authStoreFake{user: model.User{ID: 7, Email: "fixture@example.test", Password: password, Enabled: true}}
	codec := &tokenCodecFake{store: store}
	return NewAuth(store, codec), store, codec
}

func TestAuthOperationsWithoutGin(t *testing.T) {
	for _, operation := range []string{"login", "refresh", "access", "signup"} {
		t.Run(operation, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			ctx := context.WithValue(context.Background(), struct{}{}, "fixture")
			var err error

			switch operation {
			case "login":
				var pair TokenPair
				pair, err = auth.SignIn(ctx, "fixture@example.test", "fixture-password")
				if pair.AccessToken != "synthetic-access" || pair.RefreshToken != "synthetic-refresh" {
					t.Fatal("signin pair changed")
				}
			case "refresh":
				_, err = auth.RefreshSession(ctx, "fixture-refresh")
				if !reflect.DeepEqual(codec.purposes, []TokenType{RefreshToken}) {
					t.Fatal("refresh purpose changed")
				}
			case "access":
				var user *model.User
				user, err = auth.AuthenticateAccessToken(ctx, "fixture-access")
				if user != &store.user || !reflect.DeepEqual(codec.purposes, []TokenType{AccessToken}) {
					t.Fatal("access identity/purpose changed")
				}
			case "signup":
				var user UserWithoutSecret
				user, err = auth.SignUp(ctx, SignUpInput{Email: "fixture@example.test", Password: "fixture-password", FirstName: "First", LastName: "Last"})
				if user.ID != 7 || user.Email != "fixture@example.test" || store.created.Password != store.user.Password {
					t.Fatal("signup compatibility changed")
				}
			}

			if err != nil {
				t.Fatal("operation failed")
			}
			for _, actual := range store.contexts {
				if actual != ctx {
					t.Fatal("request context replaced")
				}
			}
			if operation == "login" || operation == "refresh" {
				if store.saved == nil || store.saved.UserID != 7 || store.saved.AccessToken != "synthetic-access" || store.transactions != 1 {
					t.Fatal("session mapping changed")
				}
			}
		})
	}
}

func TestSignupDefaultRole(t *testing.T) {
	auth, store, _ := authFixture(t)

	_, err := auth.SignUp(context.Background(), SignUpInput{Email: "fixture@example.test", Password: "fixture-password"})

	if err != nil || store.created == nil || store.created.Roles != `["STANDARD_USER"]` || !store.created.Enabled {
		t.Fatal("signup did not enforce the single standard role and enabled default")
	}
}

func TestDisabledUserRejected(t *testing.T) {
	for _, operation := range []string{"login", "refresh", "access"} {
		t.Run(operation, func(t *testing.T) {
			auth, store, _ := authFixture(t)
			store.count = 6
			for _, enabled := range []bool{true, false, true} {
				store.user.Enabled = enabled
				store.trace, store.saved, store.transactions = nil, nil, 0
				want := ErrInvalidToken
				wantTrace := []string{"validate", "find_id"}
				var err error

				switch operation {
				case "login":
					want = ErrInvalidCredentials
					wantTrace = []string{"find_email"}
					var pair TokenPair
					pair, err = auth.SignIn(context.Background(), "fixture@example.test", "fixture-password")
					if !enabled && pair != (TokenPair{}) {
						t.Fatal("disabled login returned tokens")
					}
				case "refresh":
					var pair TokenPair
					pair, err = auth.RefreshSession(context.Background(), "fixture-refresh")
					if !enabled && pair != (TokenPair{}) {
						t.Fatal("disabled refresh returned tokens")
					}
				case "access":
					var user *model.User
					user, err = auth.AuthenticateAccessToken(context.Background(), "fixture-access")
					if !enabled && user != nil {
						t.Fatal("disabled access returned identity")
					}
				}

				if enabled {
					if err != nil {
						t.Fatal("enabled user rejected")
					}
					if operation != "access" {
						wantTrace = append(wantTrace, "sign", "begin", "count", "delete", "save", "commit")
					}
				} else if !errors.Is(err, want) || store.transactions != 0 || store.saved != nil {
					t.Fatal("disabled user rejection changed classification or wrote a session")
				}
				if !reflect.DeepEqual(store.trace, wantTrace) {
					t.Fatal("operation did not use current state or disabled user reached issuance")
				}
			}
		})
	}
}

func TestSignInStorageFailure(t *testing.T) {
	auth, store, _ := authFixture(t)
	failure := errors.New("synthetic-private-dsn")
	store.findErr = failure

	pair, err := auth.SignIn(context.Background(), "fixture@example.test", "fixture-password")

	if !errors.Is(err, failure) || errors.Is(err, ErrInvalidCredentials) || pair != (TokenPair{}) || store.transactions != 0 {
		t.Fatal("storage failure became credentials or success")
	}
}

func TestInvalidCredentialsAreIndistinguishable(t *testing.T) {
	var responses []error
	for _, missing := range []bool{true, false} {
		auth, store, _ := authFixture(t)
		if missing {
			store.findErr = ErrUserNotFound
		}

		pair, err := auth.SignIn(context.Background(), "fixture@example.test", "wrong-password")

		if !errors.Is(err, ErrInvalidCredentials) || pair != (TokenPair{}) || store.transactions != 0 {
			t.Fatal("invalid credentials reached issuance")
		}
		responses = append(responses, err)
	}
	if responses[0].Error() != responses[1].Error() {
		t.Fatal("unknown account and wrong password differ")
	}
}

func TestTokenAuthenticationFailures(t *testing.T) {
	for _, operation := range []string{"refresh", "access"} {
		for _, failure := range []string{"invalid_token", "missing_user", "storage"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				auth, store, codec := authFixture(t)
				want := ErrInvalidToken
				switch failure {
				case "invalid_token":
					codec.validateErr = ErrInvalidToken
				case "missing_user":
					store.findErr = ErrUserNotFound
				case "storage":
					want = errors.New("private-storage-error")
					store.findErr = want
				}
				var err error

				if operation == "refresh" {
					var pair TokenPair
					pair, err = auth.RefreshSession(context.Background(), "synthetic-refresh")
					if pair != (TokenPair{}) {
						t.Fatal("failed refresh returned pair")
					}
				} else {
					var user *model.User
					user, err = auth.AuthenticateAccessToken(context.Background(), "synthetic-access")
					if user != nil {
						t.Fatal("failed authentication returned identity")
					}
				}

				if !errors.Is(err, want) || store.transactions != 0 {
					t.Fatal("token failure classification changed")
				}
				if failure == "invalid_token" && !reflect.DeepEqual(store.trace, []string{"validate"}) {
					t.Fatal("invalid token queried user")
				}
			})
		}
	}
}

func TestSessionIssuanceFailures(t *testing.T) {
	for _, failure := range []string{"sign", "count", "delete", "save", "commit", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			store.count = 6
			expected := errors.New("private-operation-failure")
			ctx := context.Background()
			wantTrace := []string{"find_email", "sign", "begin"}
			switch failure {
			case "sign":
				codec.issueErr = expected
				wantTrace = wantTrace[:2]
			case "count":
				store.countErr = expected
				wantTrace = append(wantTrace, "count")
			case "delete":
				store.deleteErr = expected
				wantTrace = append(wantTrace, "count", "delete")
			case "save":
				store.saveErr = expected
				wantTrace = append(wantTrace, "count", "delete", "save")
			case "commit":
				store.commitErr = expected
				wantTrace = append(wantTrace, "count", "delete", "save", "commit")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				expected = context.Canceled
			}

			pair, err := auth.SignIn(ctx, "fixture@example.test", "fixture-password")

			if !errors.Is(err, expected) || pair != (TokenPair{}) || !reflect.DeepEqual(store.trace, wantTrace) {
				t.Fatal("failed issuance returned success or continued")
			}
			wantTransactions := 1
			if failure == "sign" {
				wantTransactions = 0
			}
			if store.transactions != wantTransactions {
				t.Fatal("issuance retried or wrote before signing")
			}
		})
	}
}

func TestSessionCleanupPreservesCurrentThreshold(t *testing.T) {
	for _, count := range []int64{5, 6} {
		auth, store, _ := authFixture(t)
		store.count = count
		want := []string{"find_email", "sign", "begin", "count"}
		if count > 5 {
			want = append(want, "delete")
		}
		want = append(want, "save", "commit")

		_, err := auth.SignIn(context.Background(), "fixture@example.test", "fixture-password")

		if err != nil || !reflect.DeepEqual(store.trace, want) {
			t.Fatal("legacy cleanup threshold/order changed")
		}
	}
}

func TestSignupBirthday(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"", true}, {"2000-02-29", true}, {"2001-02-29", false}, {"2026-04-31", false}, {"2026-13-01", false}, {"01-01-2000", false},
	} {
		t.Run(test.value, func(t *testing.T) {
			auth, store, _ := authFixture(t)

			user, err := auth.SignUp(context.Background(), SignUpInput{Email: "fixture@example.test", Password: "fixture-password", Birthday: test.value})

			if !test.valid {
				if !errors.Is(err, ErrInvalidInput) || store.created != nil || user != (UserWithoutSecret{}) {
					t.Fatal("invalid birthday wrote user")
				}
				return
			}
			if err != nil || store.created == nil {
				t.Fatal("valid birthday rejected")
			}
			if test.value == "" {
				if !user.Birthday.IsZero() || !store.created.Birthday.IsZero() {
					t.Fatal("omitted birthday representation changed")
				}
			} else if user.Birthday != time.Date(2000, 2, 29, 0, 0, 0, 0, time.UTC) || store.created.Birthday != user.Birthday {
				t.Fatal("birthday parsed incorrectly")
			}
		})
	}
}

func TestSignupStorageFailure(t *testing.T) {
	for _, failure := range []error{ErrEmailExists, errors.New("private-insert-failure")} {
		auth, store, _ := authFixture(t)
		store.createErr = failure

		user, err := auth.SignUp(context.Background(), SignUpInput{Email: "fixture@example.test", Password: "fixture-password"})

		if !errors.Is(err, failure) || user != (UserWithoutSecret{}) {
			t.Fatal("signup storage failure became success")
		}
	}
}
