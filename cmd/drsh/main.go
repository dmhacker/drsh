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
	cfgFilename = ""
	rootCmd     = &cobra.Command{
		Use:   "drsh",
		Short: "A supplement to ssh with an intermediate proxy",
		Long: `drsh attempts to emulate the same core functionality as ssh, except
rather than setting up a direct connection between server & client, packets are 
instead routed through a message broker in form of a Redis instance.`,
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
through Redis. All clients are assumed to be connecting using an interactive
session, requiring the use of a pty.`,
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
		Long: `Calculate the RTT from the current machine to the specified server.
Connection strings are either provided as an alias in the config or in raw format.`,
		Run: runPing,
	}
)

func runConfig(cmd *cobra.Command, args []string) {
	if err := drshconf.WriteDefaultConfig(cfgFilename); err != nil {
		er(err)
	}
	fmt.Printf("The default config has been written to '%s'.\n", cfgFilename)
	fmt.Printf("Please edit it before running a server or client.\n")
}

func runServe(cmd *cobra.Command, args []string) {
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	logger := drshconf.NewLogger("server", &cfg)
	defer logger.Sync()
	sugar := logger.Sugar()

	serv, err := drshhost.NewServer(cfg.Server.Hostname, cfg.Server.RedisURI, sugar)
	if err != nil {
		er(err)
	}
	defer serv.Close()
	serv.Start()

	sugar.Infof("Started server '%s' with uid %d", cfg.Server.Hostname, syscall.Getuid())
	fmt.Printf("The server has been started. Logs are kept at %s.\n", cfg.Server.LogFile)
	<-make(chan bool)
}

func newClientFromCommand(cmd *cobra.Command, args []string) *drshhost.Client {
	cfg := drshconf.Config{}
	if err := drshconf.ReadConfig(cfgFilename, &cfg); err != nil {
		er(err)
	}

	logger := drshconf.NewLogger("client", &cfg)
	defer logger.Sync()
	sugar := logger.Sugar()

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
			Username: components[0],
			Hostname: components[1],
			RedisURI: strings.Join(components[2:], "@"),
		}
	}

	clnt, err := drshhost.NewClient(selection.Username, selection.Hostname, selection.RedisURI, sugar)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	sugar.Infof("Started client with connection to %s@%s", selection.Username, selection.Hostname)
	return clnt
}

func runLogin(cmd *cobra.Command, args []string) {
	clnt := newClientFromCommand(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.LoginInteractively(); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		er(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
	    fmt.Printf("Connection to remote server closed.\n")
	}
}

func runUpload(cmd *cobra.Command, args []string) {
	clnt := newClientFromCommand(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.UploadFile(os.Args[3], os.Args[4]); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		er(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
	    fmt.Printf("File uploaded to remote server.\n")
	}
}

func runDownload(cmd *cobra.Command, args []string) {
	clnt := newClientFromCommand(cmd, args)
	defer clnt.Close()
	clnt.Start()
	if err := clnt.DownloadFile(os.Args[3], os.Args[4]); err != nil {
		clnt.Host.Logger.Infof("Client exited with error: %s", err)
		er(err)
	} else {
		clnt.Host.Logger.Info("Client exited normally.")
	    fmt.Printf("File downloaded from remote server.\n")
	}
}

func runPing(cmd *cobra.Command, args []string) {
	clnt := newClientFromCommand(cmd, args)
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
	cfgCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	serveCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	loginCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")
	pingCmd.Flags().StringVarP(&cfgFilename, "config", "C", defCfgFilename, "Use the specified config file")

	rootCmd.AddCommand(cfgCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(pingCmd)

	rootCmd.Execute()
}
