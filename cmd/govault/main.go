package main

import (
	"github.com/nsgo-dev/nsgo"
	"github.com/nsgo-dev/nsgo/core"
)

func main() {
	nsgo.Run(App, nsgo.WindowSize(980, 640))
}

func App(app *core.Scope) {
	NewDesktopShell(app)
}
