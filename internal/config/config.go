package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type ServerConfig struct {
	Hostname string `mapstructure:"hostname"`
	RedisUri string `mapstructure:"redis_uri"`
}

type AliasEntry struct {
	Alias    string `mapstructure:"alias"`
	User     string `mapstructure:"user"`
	Hostname string `mapstructure:"hostname"`
	RedisUri string `mapstructure:"redis_uri"`
}

type ClientConfig struct {
	Aliases []AliasEntry `mapstructure:"aliases"`
}

func ConfigHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if len(configHome) == 0 {
		configHome = filepath.Join(home, ".config")
	}
	return configHome, nil
}

func DefaultServerConfig() (string, error) {
	configHome, err := ConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "drshd", "config.yml"), nil
}

func DefaultClientConfig() (string, error) {
	configHome, err := ConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "drsh", "config.yml"), nil
}

func ReadConfig(filename string, rawVal interface{}) error {
	viper.SetConfigFile(filename)
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := viper.Unmarshal(rawVal); err != nil {
		return err
	}
	return nil
}
