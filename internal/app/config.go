package app

import (
	"os"
	"strings"
)

type Config struct {
	NATSUser      string
	NATSPassword  string
	NATSEndpoints []string

	TunnelEndpoint string
	LocalPort      string
}

var globalCfg Config

func GetConfig() *Config {
	return &globalCfg
}

func initConfig() {
	globalCfg = Config{
		TunnelEndpoint: os.Getenv("TUNNEL_ENDPOINT"),
		LocalPort:      os.Getenv("LOCAL_PORT"),
		NATSUser:       os.Getenv("NATS_USER"),
		NATSPassword:   os.Getenv("NATS_PASSWORD"),
		NATSEndpoints:  strings.Split(os.Getenv("NATS_ENDPOINTS"), ","),
	}
}
