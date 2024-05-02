package database

import (
	"auth/internal/service/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os/user"
)

var DB *gorm.DB

func Database() {
	conf := config.DB()

	dsn := "host=" + conf.Host + " user=" + conf.Username + " password=" + conf.Password + " dbname=" + conf.DbName + " port=" + conf.Port + " sslmode=disable"
	connection, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to main database!")
	}

	DB = connection
	migrationList()
}

func migrationList() {
	err := DB.AutoMigrate(user.User{})
	if err != nil {
		return
	}
}
