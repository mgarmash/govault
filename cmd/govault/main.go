package main

import (
	"flag"

	"github.com/nsgo-dev/nsgo"
	"github.com/nsgo-dev/nsgo/core"
)

var demoFlag = flag.Bool("demo", false, "run with an in-memory sample vault")

func main() {
	flag.Parse()
	nsgo.Run(App, nsgo.WindowSize(1100, 720))
}

func App(app *core.Scope) {
	NewDesktopShell(app, *demoFlag)
}
