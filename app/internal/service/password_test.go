package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func legacyPassword(password string) string {
	sum := sha256.Sum256([]byte(password + "your_salt"))
	return hex.EncodeToString(sum[:])
}

func TestPasswordFormats(t *testing.T) {
	for _, password := range []string{"", "пароль🔐你好", strings.Repeat("long", 256)} {
		encoded, err := HashPassword(password)
		if err != nil {
			t.Fatal("hash failed")
		}

		valid, upgrade, err := VerifyPassword(password, encoded)

		if err != nil || !valid || upgrade || !strings.HasPrefix(encoded, passwordPrefix) {
			t.Fatal("new format failed round trip")
		}
		valid, upgrade, err = VerifyPassword(password+"x", encoded)
		if err != nil || valid || upgrade {
			t.Fatal("new format accepted wrong password or truncated input")
		}
		for _, legacy := range []string{legacyPassword(password), strings.ToUpper(legacyPassword(password))} {
			valid, upgrade, err = VerifyPassword(password, legacy)
			if err != nil || !valid || !upgrade {
				t.Fatal("legacy credential failed or did not require upgrade")
			}
			valid, upgrade, err = VerifyPassword(password+"x", legacy)
			if err != nil || valid || upgrade {
				t.Fatal("wrong legacy password requested upgrade")
			}
		}
	}
}

func TestPasswordRandomSalts(t *testing.T) {
	first, err := HashPassword("same-password")
	if err != nil {
		t.Fatal("first hash failed")
	}
	second, err := HashPassword("same-password")
	if err != nil {
		t.Fatal("second hash failed")
	}

	firstSalt, _, err := parsePassword(first)
	if err != nil {
		t.Fatal("first format failed")
	}
	secondSalt, _, err := parsePassword(second)
	if err != nil || string(firstSalt) == string(secondSalt) || first == second {
		t.Fatal("password hashes reused salt")
	}
}

func TestPasswordEncodingBounds(t *testing.T) {
	salt := strings.Repeat("A", passwordSaltEncodedBytes)
	key := strings.Repeat("A", passwordKeyEncodedBytes)
	supported := passwordPrefix + salt + "$" + key
	invalid := []string{
		"", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("x", 1<<20), supported + "$", supported + "extra",
		strings.Replace(supported, "argon2id", "argon2i", 1),
		strings.Replace(supported, "v=19", "v=16", 1),
		strings.Replace(supported, "m=65536", "m=65535", 1),
		strings.Replace(supported, "m=65536", "m=4294967295", 1),
		strings.Replace(supported, "t=3", "t=0", 1),
		strings.Replace(supported, "t=3", "t=4294967295", 1),
		strings.Replace(supported, "p=4", "p=0", 1),
		strings.Replace(supported, "p=4", "p=255", 1),
		strings.Replace(supported, "p=4", "p=04", 1),
		strings.Replace(supported, "m=65536,t=3,p=4", "t=3,m=65536,p=4", 1),
		passwordPrefix + salt[1:] + "$" + key,
		passwordPrefix + salt + "A$" + key,
		passwordPrefix + salt + "=$" + key,
		passwordPrefix + salt + "$" + key[1:],
		passwordPrefix + salt + "$" + key + "A",
		passwordPrefix + salt + "$" + key[:42] + "B",
		passwordPrefix + salt[:21] + "B$" + key,
		passwordPrefix + salt[:21] + "!$" + key,
		passwordPrefix + salt[:21] + "\n$" + key,
		passwordPrefix + salt + "$" + key[:42] + "!",
	}
	for i, encoded := range invalid {
		valid, upgrade, err := VerifyPassword("fixture-password", encoded)

		if !errors.Is(err, errPasswordEncoding) || valid || upgrade || strings.Contains(err.Error(), encoded) && len(encoded) > 0 {
			t.Fatalf("invalid encoding case %d did not fail safely", i)
		}
	}
}

type failingRandom struct{}

func (failingRandom) Read([]byte) (int, error) { return 0, errors.New("private-random-source-failure") }

func TestHashPasswordRandomFailure(t *testing.T) {
	for _, random := range []io.Reader{failingRandom{}, strings.NewReader("short")} {
		encoded, err := hashPassword("fixture-password", random)

		if err == nil || encoded != "" || strings.Contains(err.Error(), "private-random") {
			t.Fatal("random failure returned a credential or private diagnostics")
		}
	}
}

func BenchmarkHashPassword(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := HashPassword("benchmark-password"); err != nil {
			b.Fatal("hash failed")
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	encoded, err := HashPassword("benchmark-password")
	if err != nil {
		b.Fatal("fixture hash failed")
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		valid, upgrade, err := VerifyPassword("benchmark-password", encoded)
		if err != nil || !valid || upgrade {
			b.Fatal("verify failed")
		}
	}
}
