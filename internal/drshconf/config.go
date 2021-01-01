package drshconf

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/viper"
)

// AliasEntry consists of a unique name (alias), a username, a hostname, and Redis URI to connect to.
type AliasEntry struct {
	Alias    string `mapstructure:"alias"`
	Username string `mapstructure:"username"`
	Hostname string `mapstructure:"hostname"`
	RedisURI string `mapstructure:"redisuri"`
}

// Config consists of sections for the server and client. It will be used by all invocations of `drsh`.
type Config struct {
	Server struct {
		Hostname string `mapstructure:"hostname"`
		RedisURI string `mapstructure:"redisuri"`
	} `mapstructure:"server"`
	Client struct {
		Aliases []AliasEntry `mapstructure:"aliases"`
	} `mapstructure:"client"`
}

// DefaultConfigFilename returns the default location of the config file on the user's system.
func DefaultConfigFilename() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if len(configHome) == 0 {
		configHome = filepath.Join(home, ".config")
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "drsh", "config.yml"), nil
}

// WriteDefaultConfig will write a default config if one does not exist already.
// It will also create any necessary nested parent directories.
func WriteDefaultConfig(filename string) error {
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
		{
			Alias:    currHostname,
			Username: currUser.Username,
			Hostname: currHostname,
			RedisURI: "redis://localhost:6379",
		},
	})
	if err := os.MkdirAll(filepath.Dir(filename), 0777); err != nil {
		return err
	}
	if err := viper.SafeWriteConfigAs(filename); err != nil {
		return err
	}
	return nil
}

// ReadConfig reads the given config file into the Config data structure.
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
