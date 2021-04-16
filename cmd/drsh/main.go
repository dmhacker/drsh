package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	drshconf "github.com/dmhacker/drsh/internal/drsh/conf"
	drshhost "github.com/dmhacker/drsh/internal/drsh/host"
	"github.com/spf13/cobra"
)

var (
	version     = "v1.5.3"
	cfgFilename = ""
	rootCmd     = &cobra.Command{
		Use:   "drsh",
		Short: "A supplement to ssh with an intermediate proxy",
		Long: `drsh attempts to emulate the same core functionality as ssh, except
rather than setting up a direct connection between server & client, packets are 
instead routed through Redis.`,
	}
	cfgCmd = &cobra.Command{
		Use:   "config",
		Short: "Create a default config if one does not exist",
		Long: `If a config file does not exist at the given path,
it will create a default file. drsh should not be run with the default settings
but the default config provides a useful starting point.`,
		Run: runConfig,
	}
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the drsh daemon for this machine",
		Long: `Actively listen for connection requests from other clients on the
Redis network. Functions similarily to sshd, only all packets are routed
through Redis.`,
		Run: runServe,
	}
	loginCmd = &cobra.Command{
		Use:   "login [alias|user@host@redis]",
		Args:  cobra.ExactArgs(1),
		Short: "Log in to a remote server",
		Long: `Open a secure, interactive shell to a host on the Redis network using the given 
hostname and username. Connection strings are either provided as a 
config-defined alias  or in raw format. The session is assumed to be interactive;
there is no option to disable the pty at the moment.`,
		Run: runLogin,
	}
	uploadCmd = &cobra.Command{
		Use:   "upload [alias|user@host@redis] [local_file] [remote_file]",
		Args:  cobra.ExactArgs(3),
		Short: "Upload a file to a remote server",
		Long: `Upload a locally hosted file to a remote server.
The remote filename should be specified from the perspective of the remote user's home directory.`,
		Run: runUpload,
	}
	downloadCmd = &cobra.Command{
		Use:   "download [alias|user@host@redis] [remote_file] [local_file]",
		Args:  cobra.ExactArgs(3),
		Short: "Download a file from a remote server",
		Long: `Download a file hosted on a remote server and saves the content to a local file.
The remote filename should be specified from the perspective of the remote user's home directory.`,
		Run: runDownload,
	}
	pingCmd = &cobra.Command{
		Use:   "ping [alias|user@host@redis]",
		Args:  cobra.ExactArgs(1),
		Short: "Ping a remote server",
		Long: `Calculate the round-trip time from the current machine to the specified server.
Connection strings are either provided as an alias in the config or in raw format.`,
		Run: runPing,
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Displays the current version of this software",
		Long:  `Displays the current version of this software.`,
		Run:   runVersion,
	}
)

func runConfig(cmd *cobra.Command, args []string) {
	if err := drshconf.WriteDefaultConfig(cfgFilename); err != nil {
		terminate(err)
	}
	fmt.Printf("The default config has been written to '%s'.\n", cfgFilename)
	fmt.Printf("Please edit it before running a server or client.\n")
}

func runServe(cmd *cobra.Command, args []string) {
	// Initialize config & logging
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		terminate(err)
	}
	logger := drshconf.NewLogger("server", &cfg)
	defer logger.Sync()
	// Initialize and start server
	serv, err := drshhost.NewServer(cfg.Server.Hostname, cfg.Server.RedisURI, logger.Sugar())
	if err != nil {
		terminate(err)
	}
	defer serv.Close()
	serv.Start()
	serv.Host.Logger.Infof("Server '%s' under uid %d is now listening for connections.", cfg.Server.Hostname, syscall.Getuid())
	fmt.Printf("Server has been started. Logs are kept at %s.\n", cfg.Server.LogFile)
	<-make(chan bool)
}

func newClient(cmd *cobra.Command, args []string) *drshhost.Client {
	// Initialize config & logging
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		terminate(err)
	}
	logger := drshconf.NewLogger("client", &cfg)
	defer logger.Sync()
	// Attempt to resolve alias using config
	rawSelection := args[0]
	var selection drshconf.AliasEntry
	var selected bool = false
	for _, entry := range cfg.Client.Aliases {
		if rawSelection == entry.Alias {
			selection = entry
			selected = true
			break
		}
	}
	// If no alias matches, then interpret it directly
	if !selected {
		components := strings.Split(rawSelection, "@")
		if len(components) < 3 {
			terminate(fmt.Errorf("command should either be an alias or in the format USER@HOST@URI"))
		}
		selection = drshconf.AliasEntry{
			Username: components[0],
			Hostname: components[1],
			RedisURI: strings.Join(components[2:], "@"),
		}
	}
	// Initialize and start client
	clnt, err := drshhost.NewClient(selection.Username, selection.Hostname, selection.RedisURI, logger.Sugar())
	if err != nil {
		terminate(err)
	}
	clnt.Host.Logger.Infof("Client started. Connecting to %s@%s.", selection.Username, selection.Hostname)
	return clnt
}

func runLogin(cmd *cobra.Command, args []string) {
	clnt := newClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.LoginInteractively(); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		terminate(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
		fmt.Printf("Connection to remote server closed.\n")
	}
}

func runUpload(cmd *cobra.Command, args []string) {
	clnt := newClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.UploadFile(args[1], args[2]); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		terminate(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
		fmt.Printf("File uploaded to remote server.\n")
	}
}

func runDownload(cmd *cobra.Command, args []string) {
	clnt := newClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.DownloadFile(args[1], args[2]); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		terminate(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
		fmt.Printf("File downloaded from remote server.\n")
	}
}

func runPing(cmd *cobra.Command, args []string) {
	clnt := newClient(cmd, args)
	defer clnt.Close()
	clnt.Start()
	clnt.Ping()
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println(version)
}

func terminate(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	defCfgFilename, err := drshconf.DefaultConfigFilename()
	if err != nil {
		terminate(err)
	}
	// Set up flags for subcommands
	cfgCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	serveCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	loginCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	pingCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	// Add subcommands to the root command
	rootCmd.AddCommand(cfgCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(pingCmd)
	rootCmd.AddCommand(versionCmd)
	// Execute the root command
	rootCmd.Execute()
}
