package app

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
)

var (
	Version string
	Info    = make(map[string]any)
)

func Init() {
	revision, vcsTime := readRevisionTime()

	Info["version"] = Version
	Info["revision"] = revision

	validateEnvironment()
	initConfig()

	platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	log.Logger.Info().
		Str("version", Version).
		Str("platform", platform).
		Str("revision", revision).
		Msg("camera.ui cloud")

	log.Logger.Debug().
		Str("go_version", runtime.Version()).
		Str("vcs.time", vcsTime).
		Msg("build info")
}

func validateEnvironment() {
	required := []string{
		"SERVER_ID",
		"SERVER_PRIV_KEY",
		"SERVER_KEY_ID",
		"CLOUD_ENDPOINT",
		"LOCAL_PORT",
		"NATS_ENDPOINTS",
		"NATS_USER",
		"NATS_PASSWORD",
	}

	var missing []string
	for _, env := range required {
		if os.Getenv(env) == "" {
			missing = append(missing, env)
		}
	}

	if len(missing) > 0 {
		log.Logger.Fatal().
			Strs("missing_vars", missing).
			Msg("Required environment variables are missing")
	}
}

func readRevisionTime() (revision, vcsTime string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if len(setting.Value) > 7 {
				revision = setting.Value[:7]
			} else {
				revision = setting.Value
			}
		case "vcs.time":
			vcsTime = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	if modified {
		revision = "mod." + revision
	}
	return
}
