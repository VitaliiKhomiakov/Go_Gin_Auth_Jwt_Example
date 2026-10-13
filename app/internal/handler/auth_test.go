package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"auth/internal/model"
	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

type authFake struct {
	calls                    []string
	ctx                      context.Context
	email, password, refresh string
	input                    service.SignUpInput
	err                      error
}

func (f *authFake) SignIn(ctx context.Context, email, password string) (service.TokenPair, error) {
	f.calls = append(f.calls, "login")
	f.ctx, f.email, f.password = ctx, email, password
	return service.TokenPair{AccessToken: "fixture-access", RefreshToken: "fixture-refresh"}, f.err
}

func (f *authFake) RefreshSession(ctx context.Context, token string) (service.TokenPair, error) {
	f.calls = append(f.calls, "refresh")
	f.ctx, f.refresh = ctx, token
	return service.TokenPair{AccessToken: "fixture-access", RefreshToken: "fixture-refresh"}, f.err
}

func (f *authFake) SignUp(ctx context.Context, input service.SignUpInput) (service.UserWithoutSecret, error) {
	f.calls = append(f.calls, "signup")
	f.ctx, f.input = ctx, input
	return service.UserWithoutSecret{ID: 7, Email: input.Email, FirstName: input.FirstName, MiddleName: input.MiddleName, LastName: input.LastName, Birthday: time.Date(2000, 2, 29, 0, 0, 0, 0, time.UTC)}, f.err
}

func readAuthJSON(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal("response must be JSON")
	}

	var body map[string]any
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&body); err != nil {
		t.Fatal("response must contain JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("response must contain exactly one object")
	}

	return body
}

func TestAuthHandlerCallsOperationOnce(t *testing.T) {
	for _, name := range []string{"login", "refresh", "signup"} {
		t.Run(name, func(t *testing.T) {
			fake := &authFake{}
			h := NewAuth(fake)
			body := `{"emailOrPhone":"fixture@example.test","password":"fixture-password"}`
			call := h.Login
			if name == "refresh" {
				body = `{"refreshToken":"fixture-refresh"}`
				call = h.Refresh
			}
			if name == "signup" {
				body = `{"email":"fixture@example.test","password":"fixture-password","confirmPassword":"fixture-password","firstName":"First","middleName":"Middle","lastName":"Last","birthday":"2000-02-29","roles":"ADMIN","enabled":false}`
				call = h.SignUp
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			request := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(body)).WithContext(ctx)
			router := gin.New()
			router.POST("/auth", call)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != 200 || !reflect.DeepEqual(fake.calls, []string{name}) || fake.ctx != ctx || !errors.Is(fake.ctx.Err(), context.Canceled) {
				t.Fatal("operation count/context/status changed")
			}
			result := readAuthJSON(t, response)
			if name == "signup" {
				want := service.SignUpInput{Email: "fixture@example.test", Password: "fixture-password", FirstName: "First", MiddleName: "Middle", LastName: "Last", Birthday: "2000-02-29"}
				if fake.input != want {
					t.Fatal("signup input mapping changed")
				}
				item, ok := result["item"].(map[string]any)
				if !ok || len(result) != 1 || len(item) != 6 || item["id"] != float64(7) || item["email"] != want.Email || item["birthday"] != "2000-02-29T00:00:00Z" {
					t.Fatal("signup public allowlist changed")
				}
			} else {
				if len(result) != 2 || result["accessToken"] != "fixture-access" || result["refreshToken"] != "fixture-refresh" {
					t.Fatal("token wire contract changed")
				}
				if name == "login" && (fake.email != "fixture@example.test" || fake.password != "fixture-password") {
					t.Fatal("login input changed")
				}
				if name == "refresh" && fake.refresh != "fixture-refresh" {
					t.Fatal("refresh input changed")
				}
			}
		})
	}
}

func TestMalformedAuthBodiesStopBeforeOperations(t *testing.T) {
	tests := []struct {
		name, body string
		status     int
	}{
		{"login", "", 400}, {"login", "{", 400}, {"login", "{}", 400}, {"login", `{"emailOrPhone":"fixture@example.test"}`, 400},
		{"signup", "{", 400}, {"signup", "{}", 400}, {"signup", `{"email":"invalid","password":"x","confirmPassword":"x","firstName":"First","lastName":"Last"}`, 400},
		{"signup", `{"email":"fixture@example.test","password":"x","confirmPassword":"y","firstName":"First","lastName":"Last"}`, 400},
		{"refresh", "{", 401}, {"refresh", "{}", 401}, {"refresh", `{"refreshToken":7}`, 401},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			fake := &authFake{}
			h := NewAuth(fake)
			call := h.Login
			if test.name == "signup" {
				call = h.SignUp
			}
			if test.name == "refresh" {
				call = h.Refresh
			}
			downstream := 0
			router := gin.New()
			router.POST("/auth", call, func(c *gin.Context) { downstream++; c.JSON(200, gin.H{"unexpected": true}) })
			response := httptest.NewRecorder()

			router.ServeHTTP(response, httptest.NewRequest("POST", "/auth", strings.NewReader(test.body)))

			if response.Code != test.status || len(fake.calls) != 0 || downstream != 0 {
				t.Fatal("binding failure reached operation/downstream")
			}
			readAuthJSON(t, response)
		})
	}
}

func TestProtectedIdentityContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		present bool
		value   any
	}{
		{name: "missing"}, {name: "nil", present: true}, {name: "nil_pointer", present: true, value: (*model.User)(nil)},
		{name: "wrong_type", present: true, value: "invalid"}, {name: "value", present: true, value: model.User{ID: 7}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := NewAuth(&authFake{})
			downstream := 0
			router := gin.New()
			router.GET("/auth", func(c *gin.Context) {
				if test.present {
					c.Set("user", test.value)
				}
			}, h.Me, func(c *gin.Context) { downstream++; c.JSON(200, gin.H{"unexpected": true}) })
			response := httptest.NewRecorder()

			router.ServeHTTP(response, httptest.NewRequest("GET", "/auth", nil))

			if response.Code != 500 || downstream != 0 || readAuthJSON(t, response)["error"] != "Internal server error" {
				t.Fatal("invalid identity did not stop with safe 500")
			}
		})
	}

	fake := &authFake{}
	h := NewAuth(fake)
	router := gin.New()
	router.GET("/auth", func(c *gin.Context) {
		c.Set("user", &model.User{ID: 7, Email: "fixture@example.test", Password: "private", Roles: "private"})
	}, h.Me)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest("GET", "/auth", nil))

	body := readAuthJSON(t, response)
	if response.Code != 200 || len(body) != 2 || body["id"] != float64(7) || body["email"] != "fixture@example.test" || len(fake.calls) != 0 {
		t.Fatal("validate changed allowlist or repeated authentication")
	}
}

func TestAuthenticationErrorsDoNotExposeSecrets(t *testing.T) {
	for _, test := range []struct {
		err     error
		status  int
		message string
	}{
		{service.ErrInvalidCredentials, 401, "Incorrect credentials"}, {service.ErrInvalidToken, 401, "Authentication failed"},
		{service.ErrEmailExists, 409, "Email already exists"}, {service.ErrInvalidInput, 400, "Incorrect data"},
		{errors.New("synthetic-password synthetic-hash synthetic-jwt synthetic-dsn"), 500, "Internal server error"},
		{service.ErrUserNotFound, 500, "Internal server error"},
	} {
		t.Run(test.message+fmt.Sprint(test.status), func(t *testing.T) {
			fake := &authFake{err: fmt.Errorf("synthetic-secret: %w", test.err)}
			h := NewAuth(fake)
			downstream := 0
			router := gin.New()
			router.POST("/auth", h.Login, func(c *gin.Context) { downstream++ })
			response := httptest.NewRecorder()

			router.ServeHTTP(response, httptest.NewRequest("POST", "/auth", strings.NewReader(`{"emailOrPhone":"fixture@example.test","password":"synthetic-password"}`)))

			if response.Code != test.status || downstream != 0 || len(fake.calls) != 1 {
				t.Fatal("error status/count changed")
			}
			body := readAuthJSON(t, response)
			if len(body) != 1 || body["error"] != test.message {
				t.Fatal("error details were exposed")
			}
		})
	}
}

func TestHealthUsesRequestContext(t *testing.T) {
	for _, failure := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		router := gin.New()
		router.GET("/health", NewHealth(func(actual context.Context) error {
			calls++
			if actual != ctx {
				t.Fatal("health context changed")
			}
			if failure {
				return errors.New("private-dsn")
			}
			return nil
		}))
		response := httptest.NewRecorder()

		router.ServeHTTP(response, httptest.NewRequest("GET", "/health", nil).WithContext(ctx))

		status := "OK"
		if failure {
			status = "ERROR"
		}
		body := readAuthJSON(t, response)
		if response.Code != 200 || calls != 1 || len(body) != 1 || body["DataBase"] != status {
			t.Fatal("health contract changed")
		}
	}
}
