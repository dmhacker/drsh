package main

import (
	"github.com/dmhacker/drsh/internal/config"
	"github.com/dmhacker/drsh/internal/server"
	"go.uber.org/zap"
)

func main() {
	// Start the logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Read the config file
	filename, err := config.DefaultServerConfig()
	if err != nil {
		sugar.Fatalf("%s", err)
	}
	cfg := config.ServerConfig{}
	if err := config.ReadConfig(filename, &cfg); err != nil {
		sugar.Fatalf("%s", err)
	}

	// Start the server
	serv, err := server.NewServer(cfg.Hostname, cfg.RedisUri, sugar)
	if err != nil {
		sugar.Error(err)
		return
	}
	sugar.Infof("Started server '%s'", serv.Proxy.Name)
	defer serv.Close()
	serv.Start()
}
