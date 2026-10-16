// (c) go2rtc

package shell

import (
	"os"
	"os/signal"
	"syscall"
)

func RunUntilSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	println("exit with signal:", (<-sigs).String())
}
