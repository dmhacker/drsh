package drshconf

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/viper"
)

type AliasEntry struct {
	Alias    string `mapstructure:"alias"`
	User     string `mapstructure:"user"`
	Hostname string `mapstructure:"hostname"`
	RedisUri string `mapstructure:"redisuri"`
}

type Config struct {
	Server struct {
		Hostname string `mapstructure:"hostname"`
		RedisUri string `mapstructure:"redisuri"`
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
	currHostname, err := os.Hostname()
	if err != nil {
		return err
	}
	currUser, err := user.Current()
	if err != nil {
		return err
	}
	viper.SetDefault("Server.Hostname", currHostname)
	viper.SetDefault("Server.RedisUri", "redis://localhost:6379")
	viper.SetDefault("Client.Aliases", [1]AliasEntry{
		AliasEntry{
			Alias:    currHostname,
			User:     currUser.Username,
			Hostname: currHostname,
			RedisUri: "redis://localhost:6379",
		},
	})
	viper.SetConfigFile(filename)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if err := viper.WriteConfig(); err != nil {
			return err
		}
		return fmt.Errorf("A new config has been generated at '%s'. Please edit it and then rerun this command.", filename)
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	if err := viper.Unmarshal(cfg); err != nil {
		return err
	}
	return nil
}
