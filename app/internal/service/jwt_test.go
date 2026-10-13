package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
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
	if claims.ExpiresAt != codec.now().Add(15*time.Minute).Unix() || claims.TokenType != AccessToken || claims.UserID != 7 {
		t.Fatal("access claims do not match the contract")
	}
	if claims.User == nil || claims.User.ID != 7 || claims.User.Email != user.Email {
		t.Fatal("public profile was not retained")
	}

	var profile map[string]json.RawMessage
	if err := json.Unmarshal(decodedPayload(t, token), &profile); err != nil {
		t.Fatal("access payload decode failed")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(profile["user"], &fields); err != nil || len(fields) != 6 {
		t.Fatal("public profile allowlist changed")
	}

	if _, present := fields["password"]; present {
		t.Fatal("public profile exposes password")
	}
	if _, present := fields["roles"]; present {
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
	refresh, err := codec.sign(7, RefreshToken, nil)
	if err != nil {
		t.Fatal("classification refresh fixture failed")
	}

	for _, test := range []struct {
		name  string
		field string
		value json.RawMessage
	}{
		{"missing_user_id", "userID", nil},
		{"null_user_id", "userID", json.RawMessage(`null`)},
		{"zero_user_id", "userID", json.RawMessage(`0`)},
		{"negative_user_id", "userID", json.RawMessage(`-1`)},
		{"fractional_user_id", "userID", json.RawMessage(`1.5`)},
		{"string_user_id", "userID", json.RawMessage(`"7"`)},
		{"boolean_user_id", "userID", json.RawMessage(`true`)},
		{"overflow_user_id", "userID", json.RawMessage(`18446744073709551616`)},
		{"missing_exp", "exp", nil},
		{"null_exp", "exp", json.RawMessage(`null`)},
		{"zero_exp", "exp", json.RawMessage(`0`)},
		{"negative_exp", "exp", json.RawMessage(`-1`)},
		{"fractional_exp", "exp", json.RawMessage(`2000000000.5`)},
		{"string_exp", "exp", json.RawMessage(`"2000000000"`)},
		{"overflow_exp", "exp", json.RawMessage(`9223372036854775808`)},
		{"missing_purpose", "tokenType", nil},
		{"unknown_purpose", "tokenType", json.RawMessage(`"UNKNOWN"`)},
		{"wrong_purpose", "tokenType", json.RawMessage(`"REFRESH_TOKEN"`)},
		{"malformed_purpose", "tokenType", json.RawMessage(`7`)},
		{"missing_jti", "jti", nil},
		{"null_jti", "jti", json.RawMessage(`null`)},
		{"empty_jti", "jti", json.RawMessage(`""`)},
		{"whitespace_jti", "jti", json.RawMessage(`" \t"`)},
		{"malformed_jti", "jti", json.RawMessage(`7`)},
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
			if valid, err := codec.MatchesSessionContract(7, TokenPair{AccessToken: token, RefreshToken: refresh}); err != nil || valid {
				t.Fatal("invalid typed claims classified current")
			}
		})
	}

	for _, token := range []string{"", "invalid", "a.b.c"} {
		if _, err := codec.Validate(token, AccessToken); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
	old := signFixture(t, map[string]json.RawMessage{"user": json.RawMessage(`{"id":7}`), "exp": json.RawMessage(strconv.FormatInt(codec.now().Add(time.Hour).Unix(), 10))}, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey))
	if _, err := codec.Validate(old, AccessToken); err == nil {
		t.Fatal("old access contract accepted")
	}
	old = signFixture(t, map[string]json.RawMessage{"userID": json.RawMessage(`7`), "exp": json.RawMessage(strconv.FormatInt(codec.now().Add(time.Hour).Unix(), 10))}, jwt.SigningMethodHS256, []byte(codec.keys.RefreshSecretKey))
	if _, err := codec.Validate(old, RefreshToken); err == nil {
		t.Fatal("old refresh contract accepted")
	}

	claims := validFixtureClaims(codec)
	claims["userID"] = json.RawMessage(strconv.FormatUint(uint64(^uint(0)), 10))
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

			if decodedClaims(t, token).ExpiresAt != wantExpiry.Unix() {
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
	unsigned := signUnsignedFixture(t, claims)
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
			id := decodedClaims(t, token).ID
			bytes, err := hex.DecodeString(id)
			if err != nil || len(bytes) != 16 {
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

type rawFixtureClaims json.RawMessage

func (rawFixtureClaims) Valid() error { return nil }

func (c rawFixtureClaims) MarshalJSON() ([]byte, error) { return c, nil }

func validFixtureClaims(codec JWTCodec) map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"userID":    json.RawMessage(`7`),
		"exp":       json.RawMessage(strconv.FormatInt(codec.now().Add(time.Hour).Unix(), 10)),
		"tokenType": json.RawMessage(`"ACCESS_TOKEN"`),
		"jti":       json.RawMessage(`"fixture-id"`),
	}
}

func signFixture(t *testing.T, claims map[string]json.RawMessage, method *jwt.SigningMethodHMAC, key []byte) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("fixture claims encoding failed")
	}

	token, err := jwt.NewWithClaims(method, rawFixtureClaims(payload)).SignedString(key)
	if err != nil {
		t.Fatal("fixture signing failed")
	}

	return token
}

func signUnsignedFixture(t *testing.T, claims map[string]json.RawMessage) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("unsigned fixture encoding failed")
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, rawFixtureClaims(payload)).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal("unsigned fixture signing failed")
	}

	return token
}

func decodedPayload(t *testing.T, token string) []byte {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("issued token shape invalid")
	}

	payload, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		t.Fatal("issued payload decode failed")
	}

	return payload
}

func decodedClaims(t *testing.T, token string) tokenClaims {
	t.Helper()

	var claims tokenClaims
	if err := json.Unmarshal(decodedPayload(t, token), &claims); err != nil {
		t.Fatal("issued typed claims decode failed")
	}

	return claims
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

func TestStoredSessionContractClassification(t *testing.T) {
	codec := fixtureCodec()
	pair, err := codec.Issue(&model.User{ID: 7})
	if err != nil {
		t.Fatal("classification fixture failed")
	}
	later := codec
	later.now = func() time.Time { return codec.now().AddDate(1, 0, 0) }

	if valid, err := later.MatchesSessionContract(7, pair); err != nil || !valid {
		t.Fatal("elapsed expiry retired current contract")
	}
	if _, err := later.Validate(pair.RefreshToken, RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("classifier weakened strict expiry")
	}
	for _, test := range []struct {
		name  string
		owner uint
		pair  TokenPair
	}{
		{"wrong_owner", 8, pair},
		{"bad_access", 7, TokenPair{AccessToken: "obsolete", RefreshToken: pair.RefreshToken}},
		{"bad_refresh", 7, TokenPair{AccessToken: pair.AccessToken, RefreshToken: "obsolete"}},
		{"swapped", 7, TokenPair{AccessToken: pair.RefreshToken, RefreshToken: pair.AccessToken}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if valid, err := later.MatchesSessionContract(test.owner, test.pair); err != nil || valid {
				t.Fatal("invalid contract classified current")
			}
		})
	}
	for _, field := range []string{"userID", "exp", "tokenType", "jti"} {
		claims := validFixtureClaims(codec)
		delete(claims, field)
		broken := pair
		broken.AccessToken = signFixture(t, claims, jwt.SigningMethodHS256, []byte(codec.keys.AccessSecretKey))
		if valid, err := later.MatchesSessionContract(7, broken); err != nil || valid {
			t.Fatal("missing contract field accepted")
		}
	}
	for _, method := range []*jwt.SigningMethodHMAC{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		broken := pair
		broken.AccessToken = signFixture(t, validFixtureClaims(codec), method, []byte(codec.keys.AccessSecretKey))
		if valid, err := codec.MatchesSessionContract(7, broken); err != nil || valid {
			t.Fatal("non-HS256 classified current")
		}
	}
	codec.keys.RefreshSecretKey = codec.keys.AccessSecretKey
	if valid, err := codec.MatchesSessionContract(7, pair); err == nil || errors.Is(err, ErrInvalidToken) || valid {
		t.Fatal("configuration failure became obsolete row")
	}
}
