package config

import (
	"github.com/BurntSushi/toml"
	"os"
)

type DBConfig interface {
	GetDB() DBParams
}

type MainDBConfig struct {
	DB DBParams `toml:"main_database"`
}

type DBParams struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	DbName   string `toml:"dbName"`
}

const dbConfig = "db.toml"

func (c MainDBConfig) GetDB() DBParams {
	return c.DB
}

func DB() DBParams {
	var dbConfig MainDBConfig
	getConfigFile(&dbConfig)
	return dbConfig.DB
}

func getConfigFile(c DBConfig) {
	currentDir, _ := os.Getwd()
	if _, err := toml.DecodeFile(currentDir+"/config/"+dbConfig, c); err != nil {
		panic(err)
	}
}
