package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"auth/internal/model"
	"auth/internal/service/config"

	"github.com/dgrijalva/jwt-go"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	codec := fixtureCodec()
	user := &model.User{ID: 7, Email: "fixture@example.test", Password: "private-fixture", Roles: "private-roles"}
	token, err := codec.generateAccessToken(user)
	if err != nil {
		t.Fatal("access issuance failed")
	}

	userID, err := codec.Validate(token, AccessToken)
	if err != nil || userID != user.ID {
		t.Fatal("issued access token did not round trip")
	}

	claims := decodedClaims(t, token)
	if claims["exp"] != float64(codec.now().Add(15*time.Minute).Unix()) || claims["tokenType"] != string(AccessToken) || claims["userID"] != float64(7) {
		t.Fatal("access claims do not match the contract")
	}
	profile, ok := claims["user"].(map[string]any)
	if !ok || len(profile) != 6 || profile["id"] != float64(7) || profile["email"] != user.Email {
		t.Fatal("public profile was not retained")
	}
	if _, present := profile["password"]; present {
		t.Fatal("public profile exposes password")
	}
	if _, present := profile["roles"]; present {
		t.Fatal("public profile exposes roles")
	}

	publicCodec, err := NewJWTCodec(codec.keys)
	if err != nil {
		t.Fatal("valid keys rejected")
	}
	pair, err := publicCodec.Issue(user)
	if err != nil {
		t.Fatal("pair issuance failed")
	}
	for purpose, token := range map[TokenType]string{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken} {
		if id, err := publicCodec.Validate(token, purpose); err != nil || id != user.ID {
			t.Fatal("public codec did not round trip")
		}
	}

}

func TestTokenRejectsInvalidClaims(t *testing.T) {
	codec := fixtureCodec()
	for _, test := range []struct {
		name  string
		field string
		value any
	}{
		{"missing_user_id", "userID", nil},
		{"null_user_id", "userID", json.RawMessage("null")},
		{"zero_user_id", "userID", 0},
		{"negative_user_id", "userID", -1},
		{"fractional_user_id", "userID", 1.5},
		{"string_user_id", "userID", "7"},
		{"boolean_user_id", "userID", true},
		{"overflow_user_id", "userID", json.Number("18446744073709551616")},
		{"missing_exp", "exp", nil},
		{"null_exp", "exp", json.RawMessage("null")},
		{"zero_exp", "exp", 0},
		{"negative_exp", "exp", -1},
		{"fractional_exp", "exp", 2000000000.5},
		{"string_exp", "exp", "2000000000"},
		{"overflow_exp", "exp", json.Number("9223372036854775808")},
		{"missing_purpose", "tokenType", nil},
		{"unknown_purpose", "tokenType", "UNKNOWN"},
		{"wrong_purpose", "tokenType", RefreshToken},
		{"malformed_purpose", "tokenType", 7},
		{"missing_jti", "jti", nil},
		{"null_jti", "jti", json.RawMessage("null")},
		{"empty_jti", "jti", ""},
		{"whitespace_jti", "jti", " \t"},
		{"malformed_jti", "jti", 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := validFixtureClaims(codec)
			if test.value == nil {
				delete(claims, test.field)
			} else {
				claims[test.field] = test.value
			}
			token := signFixture(t, claims, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey))

			if id, err := codec.Validate(token, AccessToken); err == nil || id != 0 {
				t.Fatal("invalid claims accepted")
			}
		})
	}

	for _, token := range []string{"", "invalid", "a.b.c"} {
		if _, err := codec.Validate(token, AccessToken); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
	old := signFixture(t, jwt.MapClaims{"user": map[string]any{"id": 7}, "exp": codec.now().Add(time.Hour).Unix()}, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey))
	if _, err := codec.Validate(old, AccessToken); err == nil {
		t.Fatal("old access contract accepted")
	}
	old = signFixture(t, jwt.MapClaims{"userID": 7, "exp": codec.now().Add(time.Hour).Unix()}, jwt.SigningMethodHS256, []byte(codec.keys.RefreshSecretKey))
	if _, err := codec.Validate(old, RefreshToken); err == nil {
		t.Fatal("old refresh contract accepted")
	}

	claims := validFixtureClaims(codec)
	claims["userID"] = json.Number(strconv.FormatUint(uint64(^uint(0)), 10))
	if id, err := codec.Validate(signFixture(t, claims, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey)), AccessToken); err != nil || id != ^uint(0) {
		t.Fatal("valid maximum uint identity rejected or rounded")
	}
}

func TestTokenPurposeAndExpiry(t *testing.T) {
	codec := fixtureCodec()
	for _, purpose := range []TokenType{AccessToken, RefreshToken} {
		t.Run(string(purpose), func(t *testing.T) {
			token, err := codec.sign(7, purpose, nil)
			if err != nil {
				t.Fatal("token issuance failed")
			}
			wantExpiry := codec.now().Add(15 * time.Minute)
			other := RefreshToken
			if purpose == RefreshToken {
				wantExpiry = codec.now().AddDate(0, 1, 0)
				other = AccessToken
			}

			if decodedClaims(t, token)["exp"] != float64(wantExpiry.Unix()) {
				t.Fatal("token lifetime changed")
			}
			if _, err := codec.Validate(token, other); err == nil {
				t.Fatal("access/refresh substitution accepted")
			}
			for _, offset := range []time.Duration{-time.Second, 0, time.Second} {
				validator := codec
				validator.now = func() time.Time { return wantExpiry.Add(offset) }
				_, err := validator.Validate(token, purpose)
				if (err == nil) != (offset < 0) {
					t.Fatal("strict expiry boundary violated")
				}
			}
		})
	}

	claims := validFixtureClaims(codec)
	for _, method := range []*jwt.SigningMethodHMAC{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		token := signFixture(t, claims, method, []byte(codec.keys.AccessSecretKey))
		if _, err := codec.Validate(token, AccessToken); err == nil {
			t.Fatal("non-HS256 method accepted")
		}
	}
	unsigned := signFixture(t, claims, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	if _, err := codec.Validate(unsigned, AccessToken); err == nil {
		t.Fatal("unsigned token accepted")
	}
	wrongKey := signFixture(t, claims, jwt.SigningMethodHS256, []byte(codec.keys.RefreshSecretKey))
	if _, err := codec.Validate(wrongKey, AccessToken); err == nil {
		t.Fatal("wrong signing key accepted")
	}
	valid := signFixture(t, claims, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey))
	for _, purpose := range []TokenType{"", "UNKNOWN"} {
		if _, err := codec.Validate(valid, purpose); err == nil {
			t.Fatal("unknown expected purpose accepted")
		}
	}
}

func TestSameInstantTokensAreDistinct(t *testing.T) {
	codec := fixtureCodec()
	for _, purpose := range []TokenType{AccessToken, RefreshToken} {
		first, err := codec.sign(7, purpose, nil)
		if err != nil {
			t.Fatal("first issuance failed")
		}
		second, err := codec.sign(7, purpose, nil)
		if err != nil {
			t.Fatal("second issuance failed")
		}

		if first == second {
			t.Fatal("same-instant tokens are identical")
		}
		for _, token := range []string{first, second} {
			id, ok := decodedClaims(t, token)["jti"].(string)
			bytes, err := hex.DecodeString(id)
			if !ok || err != nil || len(bytes) != 16 {
				t.Fatal("token ID is not 128 bits")
			}
		}
	}
}

func TestTokenIssuanceRejectsInvalidInputs(t *testing.T) {
	codec := fixtureCodec()
	if _, err := codec.generateAccessToken(nil); err == nil {
		t.Fatal("nil user accepted")
	}
	if _, err := codec.sign(0, RefreshToken, nil); err == nil {
		t.Fatal("zero user ID accepted")
	}
	if _, err := codec.sign(7, "UNKNOWN", nil); err == nil {
		t.Fatal("unknown purpose accepted")
	}
	codec.keys.RefreshSecretKey = codec.keys.AccessSecretKey
	if _, err := codec.sign(7, AccessToken, nil); err == nil {
		t.Fatal("invalid signing configuration accepted")
	}

	if _, err := NewJWTCodec(config.SecretParams{}); err == nil {
		t.Fatal("missing keys accepted")
	}
	if _, err := NewJWTCodec(codec.keys); err == nil {
		t.Fatal("identical keys accepted")
	}

}

func fixtureCodec() JWTCodec {
	return JWTCodec{
		keys: config.SecretParams{AccessSecretKey: "test-access-key", RefreshSecretKey: "test-refresh-key"},
		now:  func() time.Time { return time.Date(2026, time.January, 31, 12, 0, 0, 0, time.UTC) },
	}
}

func validFixtureClaims(codec JWTCodec) jwt.MapClaims {
	return jwt.MapClaims{"userID": 7, "exp": codec.now().Add(time.Hour).Unix(), "tokenType": AccessToken, "jti": "fixture-id"}
}

func signFixture(t *testing.T, claims jwt.MapClaims, method jwt.SigningMethod, key any) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal("fixture signing failed")
	}

	return token
}

func decodedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parsed, _, err := (&jwt.Parser{}).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatal("issued claims could not be decoded")
	}

	return parsed.Claims.(jwt.MapClaims)
}

type failingEntropy struct{ calls, failOn int }

func (r *failingEntropy) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == r.failOn {
		return 0, errors.New("private-entropy-error")
	}
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

func TestJWTIssueDiscardsPartialPair(t *testing.T) {
	for _, failOn := range []int{1, 2} {
		entropy := &failingEntropy{failOn: failOn}
		previous := rand.Reader
		rand.Reader = entropy

		pair, err := fixtureCodec().Issue(&model.User{ID: 7})

		rand.Reader = previous

		if err == nil || pair != (TokenPair{}) || entropy.calls != failOn {
			t.Fatal("signing failure returned partial pair or continued")
		}
	}
}
