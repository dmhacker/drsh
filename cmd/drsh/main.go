package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dmhacker/drsh/internal/client"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type ClientConfiguration struct {
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
	config := ClientConfiguration{}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(err)
		return
	}
	if err := viper.Unmarshal(&config); err != nil {
		fmt.Println(err)
		return
	}

    // Start the logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
    sugar := logger.Sugar()

	// Start the client
	clnt, err := client.NewClient(config.Uri, sugar)
	if err != nil {
        sugar.Error(err)
        return
	}
    defer clnt.Close()
    clnt.Start()
}
