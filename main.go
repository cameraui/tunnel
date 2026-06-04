package main

import (
	"github.com/cameraui/tunnel/internal/app"
	"github.com/cameraui/tunnel/internal/proxy"
	"github.com/cameraui/tunnel/internal/tunnel"
	"github.com/cameraui/tunnel/pkg/log"
	"github.com/cameraui/tunnel/pkg/shell"
)

func main() {
	app.Version = "1.0.2"

	log.Init()
	app.Init()
	proxy.Init()
	tunnel.Init()

	shell.RunUntilSignal()
}
