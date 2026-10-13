package repository

import (
	"auth/internal/model"
	"auth/internal/system/database"
	"auth/internal/validator"
	"errors"
	"gorm.io/gorm"
	"time"
)

type UserRepository interface {
	CreateUser(signUp validator.SignUp) (model.User, error)
	GetUserByID(id uint) (*model.User, error)
	GetUserByEmail(email string) (model.User, error)
	UpdateUser(user *model.User) error
	DeleteUser(id uint) error
	CheckDatabaseConnection() error
}

type UserGormRepository struct {
	db *gorm.DB
}

func GetUserRepository() UserRepository {
	return &UserGormRepository{db: database.DB}
}

func (r *UserGormRepository) CreateUser(signUp validator.SignUp) (model.User, error) {
	birthday, _ := time.Parse("2000-01-01", signUp.Birthday)

	isUserExist, _ := r.GetUserByEmail(signUp.Email)

	if isUserExist.ID > 0 {
		return model.User{}, errors.New("user already exists")
	}

	user := model.User{
		Password:   signUp.Password,
		Email:      signUp.Email,
		Birthday:   birthday,
		FirstName:  signUp.FirstName,
		MiddleName: signUp.MiddleName,
		LastName:   signUp.LastName,
		Roles:      `["STANDARD_USER", "ADMIN"]`,
		Enabled:    true,
	}

	result := r.db.Create(&user)

	if result.Error != nil {
		panic(result.Error.Error())
	}

	return user, nil
}

func (r *UserGormRepository) GetUserByID(id uint) (*model.User, error) {
	var user model.User
	result := r.db.First(&user, id)

	if result.Error != nil {
		return &model.User{}, result.Error
	}

	return &user, nil
}

func (r *UserGormRepository) GetUserByEmail(email string) (model.User, error) {
	var user model.User
	result := r.db.First(&user, "email = ?", email)

	if result.Error != nil {
		return model.User{}, result.Error
	}

	return user, nil
}

func (r *UserGormRepository) CheckDatabaseConnection() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}

	return sqlDB.Ping()
}

func (r *UserGormRepository) UpdateUser(user *model.User) error {
	// Реализация метода UpdateUser
	return nil
}

func (r *UserGormRepository) DeleteUser(id uint) error {
	// Реализация метода DeleteUser
	return nil
}
