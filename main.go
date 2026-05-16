package main

import (
	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/proxy"
	"github.com/seydx/cameraui.com/cloud-client/internal/tunnel"
	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
	"github.com/seydx/cameraui.com/cloud-client/pkg/shell"
)

func main() {
	app.Version = "0.0.11"

	log.Init()
	app.Init()
	proxy.Init()
	tunnel.Init()

	shell.RunUntilSignal()
}
