package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type SecretKeysConfig struct {
	Secret SecretParams `toml:"secret"`
}

type SecretParams struct {
	AccessSecretKey  string `toml:"accessSecretKey"`
	RefreshSecretKey string `toml:"refreshSecretKey"`
}

func LoadSecret() (SecretParams, error) {
	var conf SecretKeysConfig
	if _, err := toml.DecodeFile(filepath.Join("config", "secret.toml"), &conf); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SecretParams{}, errors.New("token configuration file is missing")
		}

		return SecretParams{}, errors.New("token configuration could not be read or parsed")
	}

	if err := conf.Secret.Validate(); err != nil {
		return SecretParams{}, err
	}

	return conf.Secret, nil
}

func (p SecretParams) Validate() error {
	if strings.TrimSpace(p.AccessSecretKey) == "" || strings.TrimSpace(p.RefreshSecretKey) == "" {
		return errors.New("token configuration requires nonempty signing keys")
	}

	if p.AccessSecretKey == p.RefreshSecretKey {
		return errors.New("token configuration requires distinct signing keys")
	}

	return nil
}
