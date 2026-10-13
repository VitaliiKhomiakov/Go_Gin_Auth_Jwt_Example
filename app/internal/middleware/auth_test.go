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

type identityResponse struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

type middlewareTestResponse interface {
	errorResponse | identityResponse
}

func readMiddlewareJSON[T middlewareTestResponse](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var body T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		t.Fatal("response must contain JSON")
	}
	var extra json.RawMessage
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
		router.GET("/auth", AuthMiddleware(fake), func(c *gin.Context) { downstream++; c.Status(200) })
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil)
		request.Header.Set("Authorization", header)

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON[errorResponse](t, response)
		want := "Authorization header is invalid"
		if header == "" {
			want = "Authorization header is missing"
		}
		if response.Code != 401 || fake.calls != 0 || downstream != 0 || body.Error != want {
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
			c.JSON(200, identityResponse{ID: user.ID, Email: user.Email})
		})
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil).WithContext(ctx)
		request.Header.Set("Authorization", header)

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON[identityResponse](t, response)
		if response.Code != 200 || downstream != 1 || fake.calls != 1 || fake.ctx != ctx || fake.token != "fixture-token" || body != (identityResponse{ID: 7, Email: "fixture@example.test"}) {
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
		router.GET("/auth", AuthMiddleware(fake), func(c *gin.Context) { downstream++; c.Status(200) })
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/auth", nil)
		request.Header.Set("Authorization", "Bearer synthetic-jwt")

		router.ServeHTTP(response, request)

		body := readMiddlewareJSON[errorResponse](t, response)
		if response.Code != test.status || downstream != 0 || identitySet || fake.calls != 1 || body.Error != test.message {
			t.Fatal("authentication failure continued or exposed details")
		}
	}
}
