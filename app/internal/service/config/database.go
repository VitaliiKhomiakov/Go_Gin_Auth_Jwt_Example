package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

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

func LoadDB() (DBParams, error) {
	var conf MainDBConfig
	if _, err := toml.DecodeFile(filepath.Join("config", "db.toml"), &conf); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DBParams{}, errors.New("database configuration file is missing")
		}

		return DBParams{}, errors.New("database configuration could not be read or parsed")
	}

	if password, present := os.LookupEnv("AUTH_DB_PASSWORD"); present {
		if password == "" {
			return DBParams{}, errors.New("AUTH_DB_PASSWORD must not be empty")
		}

		conf.DB.Password = password
	}

	if err := conf.DB.Validate(); err != nil {
		return DBParams{}, err
	}

	return conf.DB, nil
}

func (p DBParams) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{"host", p.Host},
		{"port", p.Port},
		{"username", p.Username},
		{"dbName", p.DbName},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			return errors.New("database configuration requires " + field.name)
		}
	}

	if p.Password == "" {
		return errors.New("database configuration requires password")
	}

	port, err := strconv.Atoi(p.Port)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("database configuration port must be between 1 and 65535")
	}

	return nil
}
