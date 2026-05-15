package app

import (
	"os"
	"strings"
)

const (
	ModeDevelopment = "development"
	ModeProduction  = "production"
)

type Config struct {
	Mode string

	NATSUser      string
	NATSPassword  string
	NATSEndpoints []string

	ServerID      string
	ServerPrivKey string
	ServerKeyID   string
	CloudEndpoint string
	LocalPort     string
}

var globalCfg Config

func GetConfig() *Config {
	return &globalCfg
}

func (c *Config) IsDevelopment() bool {
	return c.Mode == ModeDevelopment
}

func initConfig() {
	mode := os.Getenv("ENV_MODE")
	if mode == "" {
		mode = ModeDevelopment
	}

	globalCfg = Config{
		Mode:          mode,
		ServerID:      os.Getenv("SERVER_ID"),
		ServerPrivKey: os.Getenv("SERVER_PRIV_KEY"),
		ServerKeyID:   os.Getenv("SERVER_KEY_ID"),
		CloudEndpoint: os.Getenv("CLOUD_ENDPOINT"),
		LocalPort:     os.Getenv("LOCAL_PORT"),
		NATSUser:      os.Getenv("NATS_USER"),
		NATSPassword:  os.Getenv("NATS_PASSWORD"),
		NATSEndpoints: strings.Split(os.Getenv("NATS_ENDPOINTS"), ","),
	}
}
