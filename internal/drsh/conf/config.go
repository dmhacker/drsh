package conf

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/viper"
)

// Represents a unique alias identifying a user remotely accessible through drsh.
type AliasEntry struct {
	Username string `mapstructure:"username"`
	Hostname string `mapstructure:"hostname"`
	RedisURI string `mapstructure:"redisuri"`
}

// Mapped directly by viper on to a config file.
type Config struct {
	Server struct {
		LogFile  string `mapstructure:"logfile"`
		Hostname string `mapstructure:"hostname"`
		RedisURI string `mapstructure:"redisuri"`
	} `mapstructure:"server"`
	Client struct {
		LogFile string                `mapstructure:"logfile"`
		Aliases map[string]AliasEntry `mapstructure:"aliases"`
	} `mapstructure:"client"`
}

// Default location of the config file on the user's system.
func DefaultConfigFilename() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".drsh", "config.yml"), nil
}

// Default location of a log file on the user's system.
func DefaultLogFilename(logName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".drsh", "logs", logName+".log"), nil
}

// Writes a default config if one does not exist already.
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
	servLogFile, err := DefaultLogFilename("server")
	if err != nil {
		return err
	}
	clntLogFile, err := DefaultLogFilename("client")
	if err != nil {
		return err
	}
	viper.SetDefault("Server.LogFile", servLogFile)
	viper.SetDefault("Server.Hostname", currHostname)
	viper.SetDefault("Server.RedisUri", "redis://localhost:6379")
	viper.SetDefault("Client.LogFile", clntLogFile)
	viper.SetDefault("Client.Aliases", map[string]AliasEntry{
		currHostname: {
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
