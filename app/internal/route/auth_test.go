package route

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"auth/internal/handler"
	"auth/internal/service"

	"github.com/gin-gonic/gin"
)

type routeAuthFake struct{ calls int }

func (f *routeAuthFake) SignIn(context.Context, string, string) (service.TokenPair, error) {
	f.calls++
	return service.TokenPair{}, errors.New("fixture")
}
func (f *routeAuthFake) RefreshSession(context.Context, string) (service.TokenPair, error) {
	f.calls++
	return service.TokenPair{}, errors.New("fixture")
}
func (f *routeAuthFake) SignUp(context.Context, service.SignUpInput) (service.UserWithoutSecret, error) {
	f.calls++
	return service.UserWithoutSecret{}, errors.New("fixture")
}

func TestAuthRouteAssembly(t *testing.T) {
	fake := &routeAuthFake{}
	authenticated := 0
	healthChecks := 0
	router := gin.New()
	InitRoute(router, handler.NewAuth(fake), func(c *gin.Context) { authenticated++; c.AbortWithStatus(401) }, handler.NewHealth(func(context.Context) error { healthChecks++; return nil }))
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/", "", 200}, {"GET", "/health", "", 200}, {"GET", "/auth/me", "", 401},
		{"POST", "/auth/login", `{"emailOrPhone":"fixture@example.test","password":"fixture-password"}`, 500},
		{"POST", "/auth/signUp", `{"email":"fixture@example.test","password":"fixture-password","confirmPassword":"fixture-password","firstName":"First","lastName":"Last"}`, 500},
		{"POST", "/auth/refresh", `{"refreshToken":"fixture-refresh"}`, 500}, {"GET", "/auth/validate", "", 404},
	} {
		response := httptest.NewRecorder()

		router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)))

		if response.Code != test.status {
			t.Fatal("route status changed")
		}
	}
	if authenticated != 1 || fake.calls != 3 || healthChecks != 1 || len(router.Routes()) != 6 {
		t.Fatal("route operation/middleware wiring changed")
	}
}
