package drshconf

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type AliasEntry struct {
	Alias    string `mapstructure:"alias"`
	User     string `mapstructure:"user"`
	Hostname string `mapstructure:"hostname"`
	RedisUri string `mapstructure:"redis_uri"`
}

type Config struct {
	Server struct {
		Hostname string `mapstructure:"hostname"`
		RedisUri string `mapstructure:"redis_uri"`
	} `mapstructure:"server"`
	Client struct {
		Aliases []AliasEntry `mapstructure:"aliases"`
	} `mapstructure:"client"`
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

func DefaultConfigFilename() (string, error) {
	configHome, err := ConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "drsh", "config.yml"), nil
}

func ReadConfig(filename string, cfg *Config) error {
	viper.SetConfigFile(filename)
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	return nil
}
