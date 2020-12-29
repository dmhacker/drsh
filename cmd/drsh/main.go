package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/dmhacker/drsh/internal/drshclient"
	"github.com/dmhacker/drsh/internal/drshconf"
	"github.com/dmhacker/drsh/internal/drshserver"
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
instead routed through a message broker in form of a Redis instance.`,
	}
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Starts the drsh daemon for this machine",
		Long: `Actively listen for connection requests from other clients on the
Redis network. Functions similarily to sshd, only all packets are routed
through Redis. All clients are assumed to be connecting using an interactive
session, requiring the use of a pty.`,
		Run: RunServe,
	}
	connectCmd = &cobra.Command{
		Use:   "connect [alias|user@host@redis]",
		Args:  cobra.ExactArgs(1),
		Short: "Connects to a drsh server",
		Long: `Connects to a host on the Redis network using the given 
hostname and username. Connection strings are either provided as a 
config-defined alias  or in raw format. The session is assumed to be interactive;
there is no option to disable the pty at the moment.`,
		Run: RunConnect,
	}
	pingCmd = &cobra.Command{
		Use:   "ping [alias|user@host@redis]",
		Args:  cobra.ExactArgs(1),
		Short: "Pings a drsh server",
		Long: `Calculates the RTT from the current machine to the specified server.
Connection strings are either provided as an alias in the config or in raw format.`,
		Run: RunPing,
	}
)

func RunServe(cmd *cobra.Command, args []string) {
	// Initialize the logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		er(err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Read the config file
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	// Start the server
	serv, err := drshserver.NewServer(cfg.Server.Hostname, cfg.Server.RedisUri, sugar)
	if err != nil {
		er(err)
	}
	defer serv.Close()
	serv.Start()
	sugar.Infof("Started server '%s' as uid %d", cfg.Server.Hostname, syscall.Getuid())
	<-make(chan bool)
}

func GetClient(cmd *cobra.Command, args []string) *drshclient.Client {
	// Initialize the logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		er(err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Read in config file and fetch aliases
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	// Try to resolve alias
	command := os.Args[2]
	var selection drshconf.AliasEntry
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
		if len(components) < 3 {
			er(fmt.Errorf("command should either be an alias or in the format USER@HOST@URI"))
		}
		selection = drshconf.AliasEntry{
			User:     components[0],
			Hostname: components[1],
			RedisUri: strings.Join(components[2:], "@"),
		}
	}

	// Return the client
	clnt, err := drshclient.NewClient(selection.User, selection.Hostname, selection.RedisUri, sugar)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return clnt
}

func RunConnect(cmd *cobra.Command, args []string) {
	clnt := GetClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	clnt.Connect()
}

func RunPing(cmd *cobra.Command, args []string) {
	clnt := GetClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	clnt.Ping()
}

func er(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	defCfgFilename, err := drshconf.DefaultConfigFilename()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	serveCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	connectCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	pingCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(pingCmd)

	rootCmd.Execute()
}
