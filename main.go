package main

import (
	"github.com/seydx/cameraui.com/tunnel/internal/app"
	"github.com/seydx/cameraui.com/tunnel/internal/proxy"
	"github.com/seydx/cameraui.com/tunnel/internal/tunnel"
	"github.com/seydx/cameraui.com/tunnel/pkg/log"
	"github.com/seydx/cameraui.com/tunnel/pkg/shell"
)

func main() {
	app.Version = "0.0.11"

	log.Init()
	app.Init()
	proxy.Init()
	tunnel.Init()

	shell.RunUntilSignal()
}
