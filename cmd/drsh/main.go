package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dmhacker/drsh/internal/client"
	"github.com/dmhacker/drsh/internal/config"
	"github.com/dmhacker/drsh/internal/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cfgFilename = ""
	rootCmd     = &cobra.Command{
		Use:   "drsh",
		Short: "A supplement to ssh with an intermediate proxy",
		Long: `drsh attempts to emulate the same core functionality as ssh, except
rather than setting up a direct connection between server & client, packets are 
instead routed through an intermediate overlay network. drsh uses Redis as a 
message broker to create this reliable network. This eliminates the need to 
configure outbound rules in a firewall that would normally need to be done in order
to make ssh work.`,
	}
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Starts the drsh daemon for this machine",
		Long: `The drsh daemon is responsible for actively listening for requests 
from other clients on the Redis network. It functions similarily to sshd, only all 
packets are routed through Redis. All clients are assumed to be connecting using
an interactive session, requiring the use of a pty.`,
		Run: RunServe,
	}
	connectCmd = &cobra.Command{
		Use:   "connect [alias|user@host@redis]",
		Args:  cobra.ExactArgs(1),
		Short: "Connects to a drshd server",
		Long: `As a client, connects to a host on the Redis network using the 
host's name and an acceptable username. Connection strings are either provided as 
an alias in the config or in raw format. The session is assumed to be interactive;
there is no option to disable the pty at the moment.`,
		Run: RunConnect,
	}
)

func RunServe(cmd *cobra.Command, args []string) {
	// Initialize the logger
	logger, err := zap.NewProduction()
	if err != nil {
		er(err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Read the config file
	cfg := config.Config{}
	if err := config.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	// Start the server
	serv, err := server.NewServer(cfg.Server.Hostname, cfg.Server.RedisUri, sugar)
	if err != nil {
		er(err)
	}
	sugar.Infof("Started server '%s'", serv.Proxy.Hostname)
	defer serv.Close()
	serv.Start()
}

func RunConnect(cmd *cobra.Command, args []string) {
	// Initialize the logger
	logger, err := zap.NewProduction()
	if err != nil {
		er(err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Read in config file and fetch aliases
	cfg := config.Config{}
	if err := config.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	// Try to resolve alias
	command := os.Args[2]
	var selection config.AliasEntry
	var selected bool = false
	for _, entry := range cfg.Client.Aliases {
		if command == entry.Alias {
			selection = entry
			selected = true
			break
		}
	}

	// If command matches no alias, then interpret it using raw format
	if !selected {
		components := strings.Split(command, "@")
		if len(components) != 2 {
			er(fmt.Errorf("command should either be an alias or in the format USER@HOST@URI"))
		}
		selection = config.AliasEntry{
			User:     components[0],
			Hostname: components[1],
			RedisUri: components[2],
		}
	}

	// Start the client
	clnt, err := client.NewClient(selection.User, selection.Hostname, selection.RedisUri, sugar)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer clnt.Close()
	clnt.Start()
}

func er(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	defCfgFilename, err := config.DefaultConfigFilename()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	serveCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file.")
	connectCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file.")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(connectCmd)

	rootCmd.Execute()
}
