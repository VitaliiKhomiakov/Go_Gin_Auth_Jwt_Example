package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"auth/internal/model"
)

type authStoreFake struct {
	user                                                        model.User
	findErr, createErr, countErr, deleteErr, saveErr, commitErr error
	rows                                                        []model.Token
	deleted                                                     []uint
	accessMissing                                               bool
	accessErr, refreshErr, replaceErr                           error
	replaceMiss                                                 bool
	lockFn                                                      func()
	count                                                       int64
	contexts                                                    []context.Context
	trace                                                       []string
	created                                                     *model.User
	saved                                                       *model.Token
	transactions                                                int
	updates                                                     int
	updateFn                                                    func(context.Context, uint, string, string) (bool, error)
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

func (f *authStoreFake) UpdatePasswordIfCurrent(ctx context.Context, id uint, current, replacement string) (bool, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "update_password")
	f.updates++
	if f.updateFn != nil {
		return f.updateFn(ctx, id, current, replacement)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if f.user.ID != id || f.user.Password != current {
		return false, nil
	}

	f.user.Password = replacement
	return true, nil
}

func (f *authStoreFake) CreateUser(ctx context.Context, user *model.User) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "create")
	f.created = user
	user.ID = 7
	return f.createErr
}

func (f *authStoreFake) WithSessionTransaction(ctx context.Context, id uint, operation func(*model.User, SessionWriter) error) error {
	f.contexts = append(f.contexts, ctx)
	f.transactions++
	f.trace = append(f.trace, "begin")
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.findErr != nil {
		return f.findErr
	}
	if f.lockFn != nil {
		f.lockFn()
	}
	if err := operation(&f.user, f); err != nil {
		return err
	}
	f.trace = append(f.trace, "commit")
	return f.commitErr
}

func (f *authStoreFake) HasAccessToken(ctx context.Context, id uint, token string) (bool, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "access_session")
	return !f.accessMissing, f.accessErr
}

func (f *authStoreFake) TokensAfter(ctx context.Context, after uint) ([]model.Token, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "page")
	if after > 0 {
		return nil, nil
	}
	rows := f.rows
	if rows == nil {
		for i := int64(0); i < f.count; i++ {
			rows = append(rows, model.Token{ID: uint(i + 1), UserID: 7})
		}
	}
	return rows, f.countErr
}

func (f *authStoreFake) DeleteTokenIDs(ctx context.Context, ids []uint) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "delete")
	f.deleted = append(f.deleted, ids...)
	return f.deleteErr
}

func (f *authStoreFake) SaveToken(ctx context.Context, pair TokenPair) error {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "save")
	f.saved = &model.Token{UserID: uint64(f.user.ID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken}
	return f.saveErr
}

func (f *authStoreFake) FindRefreshToken(ctx context.Context, token string) (model.Token, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "refresh_session")
	return model.Token{ID: 1, UserID: 7, RefreshToken: token}, f.refreshErr
}

func (f *authStoreFake) ReplaceToken(ctx context.Context, old model.Token, pair TokenPair) (bool, error) {
	f.contexts = append(f.contexts, ctx)
	f.trace = append(f.trace, "replace")
	f.saved = &model.Token{ID: old.ID, UserID: uint64(f.user.ID), AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken}
	return !f.replaceMiss, f.replaceErr
}

type tokenCodecFake struct {
	store                 *authStoreFake
	issueErr, validateErr error
	purposes              []TokenType
	issuedUser            model.User
	contractErr           error
	obsolete              bool
	validateFn            func() error
}

func (f *tokenCodecFake) Issue(user *model.User) (TokenPair, error) {
	f.store.trace = append(f.store.trace, "sign")
	f.issuedUser = *user
	return TokenPair{AccessToken: "synthetic-access", RefreshToken: "synthetic-refresh"}, f.issueErr
}

func (f *tokenCodecFake) Validate(token string, purpose TokenType) (uint, error) {
	f.purposes = append(f.purposes, purpose)
	f.store.trace = append(f.store.trace, "validate")
	if f.validateFn != nil {
		return 7, f.validateFn()
	}
	return 7, f.validateErr
}

func (f *tokenCodecFake) MatchesSessionContract(id uint, pair TokenPair) (bool, error) {
	return !f.obsolete, f.contractErr
}

var fixturePasswordOnce sync.Once
var fixturePassword string
var fixturePasswordErr error

func authFixture(t *testing.T) (*Auth, *authStoreFake, *tokenCodecFake) {
	t.Helper()
	fixturePasswordOnce.Do(func() { fixturePassword, fixturePasswordErr = HashPassword("fixture-password") })
	if fixturePasswordErr != nil {
		t.Fatal("fixture hash failed")
	}
	store := &authStoreFake{user: model.User{ID: 7, Email: "fixture@example.test", Password: fixturePassword, Enabled: true}}
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
				if !reflect.DeepEqual(codec.purposes, []TokenType{RefreshToken, RefreshToken}) {
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
				if user.ID != 7 || user.Email != "fixture@example.test" || !strings.HasPrefix(store.created.Password, passwordPrefix) {
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
			for _, enabled := range []bool{true, false, true} {
				store.user.Enabled = enabled
				store.saved = nil
				var err error

				switch operation {
				case "login":
					_, err = auth.SignIn(context.Background(), store.user.Email, "fixture-password")
				case "refresh":
					_, err = auth.RefreshSession(context.Background(), "fixture-refresh")
				case "access":
					_, err = auth.AuthenticateAccessToken(context.Background(), "fixture-access")
				}

				if enabled && err != nil {
					t.Fatal("enabled user rejected")
				}
				if !enabled {
					want := ErrInvalidToken
					if operation == "login" {
						want = ErrInvalidCredentials
					}
					if !errors.Is(err, want) || store.saved != nil {
						t.Fatal("disabled user wrote session or changed rejection")
					}
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

				if !errors.Is(err, want) {
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
	for _, failure := range []string{"sign", "page", "delete", "classify", "save", "commit", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			auth, store, codec := authFixture(t)
			store.count = 6
			expected := errors.New("private-operation-failure")
			ctx := context.Background()
			switch failure {
			case "sign":
				codec.issueErr = expected
			case "page":
				store.countErr = expected
			case "delete":
				store.deleteErr = expected
			case "classify":
				codec.contractErr = expected
			case "save":
				store.saveErr = expected
			case "commit":
				store.commitErr = expected
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				expected = context.Canceled
			}

			pair, err := auth.SignIn(ctx, store.user.Email, "fixture-password")

			if !errors.Is(err, expected) || pair != (TokenPair{}) || store.transactions != 1 {
				t.Fatal("failed issuance returned success or retried")
			}
		})
	}
}

func TestSessionCleanupKeepsLatestFourBeforeInsert(t *testing.T) {
	for _, count := range []int64{0, 4, 5, 6} {
		auth, store, _ := authFixture(t)
		store.count = count

		_, err := auth.SignIn(context.Background(), store.user.Email, "fixture-password")

		wantRemoved := int(count) - 4
		if wantRemoved < 0 {
			wantRemoved = 0
		}
		if err != nil || len(store.deleted) != wantRemoved || store.saved == nil {
			t.Fatal("latest-five retention failed")
		}
		for i, id := range store.deleted {
			if id != uint(i+1) {
				t.Fatal("retention deleted a newer session")
			}
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
