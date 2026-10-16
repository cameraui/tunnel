// (c) go2rtc

package log

import (
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
)

func Init() {
	var writer io.Writer

	switch output, path, _ := strings.Cut(modules["output"], ":"); output {
	case "stderr":
		writer = os.Stderr
	case "stdout":
		writer = os.Stdout
	case "file":
		if path == "" {
			path = "camera.ui.nvr.log"
		}
		if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			writer = f
		}
	}

	timeFormat := modules["time"]

	if writer != nil {
		if format := modules["format"]; format != "json" {
			console := &zerolog.ConsoleWriter{Out: writer}

			switch format {
			case "text":
				console.NoColor = true
			case "color":
				console.NoColor = false // useless, but anyway
			default:
				// autodetection if output support color
				// go-isatty - dependency for go-colorable - dependency for ConsoleWriter
				console.NoColor = !isatty.IsTerminal(writer.(*os.File).Fd())
			}

			if timeFormat != "" {
				console.TimeFormat = "15:04:05.000"
			} else {
				console.PartsOrder = []string{
					zerolog.LevelFieldName,
					zerolog.CallerFieldName,
					zerolog.MessageFieldName,
				}
			}

			writer = console
		}
	} else {
		writer = io.Discard
	}

	lvl, _ := zerolog.ParseLevel(modules["level"])
	Logger = zerolog.New(writer).Level(lvl)

	if timeFormat != "" {
		zerolog.TimeFieldFormat = timeFormat
		Logger = Logger.With().Timestamp().Logger()
	}
}

var Logger zerolog.Logger

// modules log levels
var modules = map[string]string{
	"format": "",
	"level":  "trace",
	"output": "stdout",
	"time":   zerolog.TimeFormatUnixMs,
}
