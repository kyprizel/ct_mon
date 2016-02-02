package utils

// Interrupt was taken from https://github.com/yandex/pandora/

import (
	"os"
	"os/signal"
)

func NotifyInterrupt() <-chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	return c
}
