package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"auth/internal/model"
	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

type accessFake struct {
	calls int
	ctx   context.Context
	token string
	user  *model.User
	err   error
}

func (f *accessFake) AuthenticateAccessToken(ctx context.Context, token string) (*model.User, error) {
	f.calls++
	f.ctx, f.token = ctx, token
	return f.user, f.err
}

func readMiddlewareJSON(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&body); err != nil {
		t.Fatal("response must contain JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("response must contain exactly one JSON object")
	}

	return body
}

func TestAuthorizationHeaderValidation(t *testing.T) {
	for _, header := range []string{"", " \t ", "A", "Bearer", "Bearer \t ", "Basic not-a-jwt", "Bearer not-a-jwt extra"} {
		fake := &accessFake{}
		downstream := 0
		router := gin.New()
		router.GET("/auth", AuthMiddleware(fake), func(c *gin.Context) { downstream++; c.JSON(200, gin.H{"unexpected": true}) })
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil)
		request.Header.Set("Authorization", header)

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON(t, response)
		want := "Authorization header is invalid"
		if header == "" {
			want = "Authorization header is missing"
		}
		if response.Code != 401 || fake.calls != 0 || downstream != 0 || len(body) != 1 || body["error"] != want {
			t.Fatal("invalid header continued")
		}
	}
}

func TestAuthorizationAcceptsBearerWhitespaceAndCase(t *testing.T) {
	for _, header := range []string{"Bearer fixture-token", "bearer fixture-token", "bEaReR fixture-token", " \tBearer\t fixture-token \t"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		user := &model.User{ID: 7, Email: "fixture@example.test"}
		fake := &accessFake{user: user}
		downstream := 0
		router := gin.New()
		router.GET("/auth", AuthMiddleware(fake), func(c *gin.Context) {
			downstream++
			identity, ok := c.Get("user")
			if !ok || identity != user {
				t.Fatal("pointer identity changed")
			}
			c.JSON(200, gin.H{"id": user.ID, "email": user.Email})
		})
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil).WithContext(ctx)
		request.Header.Set("Authorization", header)

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON(t, response)
		if response.Code != 200 || downstream != 1 || fake.calls != 1 || fake.ctx != ctx || fake.token != "fixture-token" || len(body) != 2 {
			t.Fatal("valid header/context/call contract changed")
		}
	}
}

func TestAuthenticationFailureStopsWithSafeErrors(t *testing.T) {
	for _, test := range []struct {
		err     error
		status  int
		message string
	}{
		{service.ErrInvalidToken, 401, "Authentication failed"},
		{errors.New("synthetic-jwt synthetic-password synthetic-hash synthetic-dsn"), 500, "Internal server error"},
		{nil, 500, "Internal server error"},
	} {
		fake := &accessFake{err: test.err}
		downstream := 0
		identitySet := false
		router := gin.New()
		router.Use(func(c *gin.Context) { c.Next(); _, identitySet = c.Get("user") })
		router.GET("/auth", AuthMiddleware(fake), func(c *gin.Context) { downstream++; c.JSON(200, gin.H{"unexpected": true}) })
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil)
		request.Header.Set("Authorization", "Bearer synthetic-jwt")

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON(t, response)
		if response.Code != test.status || downstream != 0 || identitySet || fake.calls != 1 || len(body) != 1 || body["error"] != test.message {
			t.Fatal("authentication failure continued or exposed details")
		}
	}
}
