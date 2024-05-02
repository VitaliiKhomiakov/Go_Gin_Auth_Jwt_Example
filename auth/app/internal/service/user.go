package service

import (
	"auth/internal/model"
	"auth/internal/repository"
	"auth/internal/validator"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

type UserWithoutSecret struct {
	ID         uint      `json:"id"`
	Email      string    `json:"email"`
	FirstName  string    `json:"firstName"`
	MiddleName string    `json:"middleName"`
	LastName   string    `json:"lastName"`
	Birthday   time.Time `json:"birthday"`
}

func CreateUser(signUp validator.SignUp) (*UserWithoutSecret, error) {
	saltedPassword := signUp.Password + "your_salt"
	hashedPassword := sha256.Sum256([]byte(saltedPassword))
	signUp.Password = hex.EncodeToString(hashedPassword[:])

	user, err := repository.GetUserRepository().CreateUser(signUp)

	return ExcludeSecret(&user), err
}

func Authenticate(email, password string) (*model.User, error) {
	user, err := repository.GetUserRepository().GetUserByEmail(email)

	if err != nil {
		return &user, err
	}

	validPassword, err := CheckPassword(password, "your_salt", user.Password)
	if err != nil {
		return nil, err
	}

	if !validPassword {
		return nil, errors.New("invalid password")
	}

	return &user, nil
}

func GetUserByID(userId uint) (*model.User, error) {
	return repository.GetUserRepository().GetUserByID(userId)
}

func CheckPassword(password, salt, storedHash string) (bool, error) {
	hashedPassword, err := hashPassword(password, salt)
	if err != nil {
		return false, err
	}

	return hashedPassword == storedHash, nil
}

func ExcludeSecret(user *model.User) *UserWithoutSecret {
	return &UserWithoutSecret{
		ID:         user.ID,
		Email:      user.Email,
		FirstName:  user.FirstName,
		MiddleName: user.MiddleName,
		LastName:   user.LastName,
		Birthday:   user.Birthday,
	}
}

func hashPassword(password, salt string) (string, error) {
	saltedPassword := password + salt
	hashedPassword := sha256.Sum256([]byte(saltedPassword))
	return hex.EncodeToString(hashedPassword[:]), nil
}
