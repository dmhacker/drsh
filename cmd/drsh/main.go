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
		os.Exit(1)
	}

	// Read in config file and fetch aliases
	filename, err := config.DefaultClientConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cfg := config.ClientConfig{}
	if err := config.ReadConfig(filename, &cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Try to resolve alias
	command := os.Args[1]
	var selection config.AliasEntry
	var selected bool = false
	for _, entry := range cfg.Aliases {
		if command == entry.Alias {
			selection = entry
			selected = true
			break
		}
	}
	// If command matches no alias, then interpret it using alias format
	if !selected {
		components := strings.Split(command, "@")
		if len(components) != 2 {
			fmt.Println("command should either be an alias or in the format USER@HOST@URI")
			os.Exit(1)
		}
		selection = config.AliasEntry{
			User:     components[0],
			Hostname: components[1],
			RedisUri: components[2],
		}
	}

	// Start the logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Start the client
	clnt, err := client.NewClient(selection.User, selection.Hostname, selection.RedisUri, sugar)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer clnt.Close()
	clnt.Start()
}
