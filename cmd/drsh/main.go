package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dmhacker/drsh/internal/client"
	"github.com/dmhacker/drsh/internal/config"
	"go.uber.org/zap"
)

type ClientConfiguration struct {
	RedisUri string
}

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s [ALIAS|USER@HOST@URI]\n", os.Args[0])
		return
	}

	// Read in config file and fetch aliases
	filename, err := config.DefaultClientConfig()
	if err != nil {
		fmt.Println(err)
		return
	}
	cfg := config.ClientConfig{}
	if err := config.ReadConfig(filename, &cfg); err != nil {
		fmt.Println(err)
		return
	}

	// Try to resolve alias
	command := os.Args[1]
	var selection *config.AliasEntry = nil
	for _, entry := range cfg.Aliases {
		if command == entry.Alias {
			selection = &entry
		}
	}
	// If command matches no alias, then interpret it using alias format
	if selection == nil {
		components := strings.Split(command, "@")
		if len(components) != 2 {
			fmt.Println("Command should be either be an alias or in the format USER@HOST@URI.")
			return
		}
		selection = &config.AliasEntry{
			User:     components[0],
			Hostname: components[1],
			RedisUri: components[2],
		}
	}

	// Start the logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Start the client
	clnt, err := client.NewClient(selection.User, selection.Hostname, selection.RedisUri, sugar)
	if err != nil {
		sugar.Error(err)
		return
	}
	defer clnt.Close()
	clnt.Start()
}
