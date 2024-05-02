package config

import (
	"github.com/BurntSushi/toml"
	"os"
)

type SecretConfig interface {
	GetSecret() SecretParams
}

type SecretKeysConfig struct {
	Secret SecretParams `toml:"secret"`
}

type SecretParams struct {
	AccessSecretKey  string `toml:"accessSecretKey"`
	RefreshSecretKey string `toml:"refreshSecretKey"`
}

const secretConfig = "secret.toml"

func (c SecretKeysConfig) GetSecret() SecretParams {
	return c.Secret
}

func Secret() SecretParams {
	var secretConfig SecretKeysConfig
	getSecretConfigFile(&secretConfig)
	return secretConfig.Secret
}

func getSecretConfigFile(c SecretConfig) {
	currentDir, _ := os.Getwd()
	if _, err := toml.DecodeFile(currentDir+"/config/"+secretConfig, c); err != nil {
		panic(err)
	}
}
