package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordPrefix           = "$argon2id$v=19$m=65536,t=3,p=4$"
	passwordSaltBytes        = 16
	passwordKeyBytes         = 32
	passwordSaltEncodedBytes = 22
	passwordKeyEncodedBytes  = 43
)

var errPasswordEncoding = errors.New("unsupported or malformed password encoding")

// HashPassword derives an Argon2id credential with a fresh random salt.
func HashPassword(password string) (string, error) {
	return hashPassword(password, rand.Reader)
}

func hashPassword(password string, random io.Reader) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", errors.New("password salt generation failed")
	}

	key := argon2.IDKey([]byte(password), salt, 3, 65536, 4, passwordKeyBytes)
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// VerifyPassword supports the current profile and the isolated legacy format.
// A valid legacy credential requires migration before issuing a session.
func VerifyPassword(password, encoded string) (valid, needsUpgrade bool, err error) {
	if len(encoded) == sha256.Size*2 {
		return verifyLegacyPassword(password, encoded)
	}

	salt, expected, err := parsePassword(encoded)
	if err != nil {
		return false, false, err
	}

	actual := argon2.IDKey([]byte(password), salt, 3, 65536, 4, passwordKeyBytes)
	return subtle.ConstantTimeCompare(actual, expected) == 1, false, nil
}

func parsePassword(encoded string) ([]byte, []byte, error) {
	if len(encoded) != len(passwordPrefix)+passwordSaltEncodedBytes+1+passwordKeyEncodedBytes || !strings.HasPrefix(encoded, passwordPrefix) {
		return nil, nil, errPasswordEncoding
	}

	parts := strings.Split(encoded[len(passwordPrefix):], "$")
	if len(parts) != 2 || len(parts[0]) != passwordSaltEncodedBytes || len(parts[1]) != passwordKeyEncodedBytes {
		return nil, nil, errPasswordEncoding
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(salt) != passwordSaltBytes || base64.RawStdEncoding.EncodeToString(salt) != parts[0] {
		return nil, nil, errPasswordEncoding
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(key) != passwordKeyBytes || base64.RawStdEncoding.EncodeToString(key) != parts[1] {
		return nil, nil, errPasswordEncoding
	}

	return salt, key, nil
}

func verifyLegacyPassword(password, encoded string) (bool, bool, error) {
	expected, err := hex.DecodeString(encoded)
	if err != nil {
		return false, false, errPasswordEncoding
	}

	actual := sha256.Sum256([]byte(password + "your_salt"))
	valid := subtle.ConstantTimeCompare(actual[:], expected) == 1
	return valid, valid, nil
}
