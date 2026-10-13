package service

import (
	"time"

	"auth/internal/model"
)

type UserWithoutSecret struct {
	ID         uint
	Email      string
	FirstName  string
	MiddleName string
	LastName   string
	Birthday   time.Time
}

func toPublicUser(user *model.User) UserWithoutSecret {
	return UserWithoutSecret{
		ID: user.ID, Email: user.Email, FirstName: user.FirstName,
		MiddleName: user.MiddleName, LastName: user.LastName, Birthday: user.Birthday,
	}
}
