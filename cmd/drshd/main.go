package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dmhacker/drsh/internal/server"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type ServerConfiguration struct {
	Name string
	Uri  string
}

func main() {
	// Read in config file and fetch variables
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s [CONFIG]\n", os.Args[0])
		return
	}
	filename := strings.Join(os.Args[1:], " ")
	viper.SetConfigName(filename)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")
	config := ServerConfiguration{}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(err)
		return
	}
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Println(err)
		return
	}

    // Start the logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
    sugar := logger.Sugar()

	// Start the server
	serv, err := server.NewServer(config.Name, config.Uri, sugar)
	if err != nil {
        sugar.Error(err)
        return
	}
    sugar.Infof("Started server '%s' with ID %s", serv.Name, serv.Proxy.Id.String())
    defer serv.Close()
    serv.Start()
}
