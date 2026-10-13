package service

import (
	"crypto/sha256"
	"encoding/hex"
)

func CheckPassword(password, salt, storedHash string) (bool, error) {
	hashedPassword, err := hashPassword(password, salt)
	if err != nil {
		return false, err
	}

	return hashedPassword == storedHash, nil
}

func hashPassword(password, salt string) (string, error) {
	saltedPassword := password + salt
	hashedPassword := sha256.Sum256([]byte(saltedPassword))
	return hex.EncodeToString(hashedPassword[:]), nil
}
