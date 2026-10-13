package model

type Token struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	UserID       uint64 `json:"user_id" gorm:"not null"`
	AccessToken  string `json:"access_token" gorm:"not null"`
	RefreshToken string `json:"refresh_token" gorm:"not null"`
}

func (Token) TableName() string {
	return "token"
}
