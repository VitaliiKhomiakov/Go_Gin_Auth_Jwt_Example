package repository

import (
	"auth/internal/model"
	"auth/internal/system/database"
	"gorm.io/gorm"
)

type TokenGormRepository struct {
	db *gorm.DB
}

type TokenRepository interface {
	SaveToken(data *model.Token) (*model.Token, error)
	GetTokensByUserId(userId uint) (*[]model.Token, error)
	CheckUserToken(userId uint, accessToken string) (bool, error)
	RemoveTokens(userId uint) (*model.Token, error)
	RemoveExpiredToken(userId uint, accessToken string) error
	GetTokenCount(userId uint) (int64, error)
}

func GetTokenRepository() TokenRepository {
	return &TokenGormRepository{db: database.DB}
}

func (r TokenGormRepository) SaveToken(token *model.Token) (*model.Token, error) {
	result := r.db.Create(&token)

	if result.Error != nil {
		panic(result.Error.Error())
	}

	return token, nil
}

func (r TokenGormRepository) GetTokensByUserId(userId uint) (*[]model.Token, error) {
	var tokens []model.Token
	result := r.db.Find(&tokens, "user_id = ?", userId)

	if result.Error != nil {
		return &[]model.Token{}, result.Error
	}

	return &tokens, nil
}

func (r TokenGormRepository) CheckUserToken(userId uint, accessToken string) (bool, error) {
	var token model.Token
	result := r.db.Where("user_id = ?", userId).Where("access_token = ?", accessToken).First(&token)

	if result.Error != nil {
		return false, result.Error
	}

	return token.ID > 0, nil
}

func (r TokenGormRepository) GetTokenCount(userId uint) (int64, error) {
	var count int64
	result := r.db.Model(model.Token{}).Where("user_id = ?", userId).Count(&count)

	if result.Error != nil {
		return 0, result.Error
	}

	return count, nil
}

func (r TokenGormRepository) RemoveTokens(userId uint) (*model.Token, error) {
	var token model.Token
	result := r.db.Model(model.Token{}).Where("user_id = ?", userId).Delete(&token)

	if result.Error != nil {
		return nil, result.Error
	}

	return &token, nil
}

func (r TokenGormRepository) RemoveExpiredToken(userId uint, accessToken string) error {
	result := r.db.
		Where("user_id = ?", userId).
		Where("access_token = ?", accessToken).
		Delete(model.Token{})

	if result.Error != nil {
		return result.Error
	}

	return nil
}
