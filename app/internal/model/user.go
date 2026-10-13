package model

import "time"

type User struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	Email      string    `json:"email" gorm:"unique;not null"`
	Password   string    `json:"password" gorm:"not null"`
	Roles      string    `json:"roles" gorm:"type:text;not null"`
	FirstName  string    `json:"firstName" gorm:"size:100"`
	MiddleName string    `json:"middleName" gorm:"size:100"`
	LastName   string    `json:"lastName" gorm:"size:100"`
	Birthday   time.Time `json:"birthday" gorm:"type:date"`
	LastLogin  time.Time `json:"lastLogin" gorm:"autoUpdateTime"`
	Enabled    bool      `json:"enabled" gorm:"not null;default:true"`
}

func (User) TableName() string {
	return "user"
}
