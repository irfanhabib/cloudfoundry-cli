package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type CreateRouteCommand struct {
	RequiredArgs flags.SpaceDomain `positional-args:"yes"`
	Hostname     string            `long:"hostname" short:"n" description:"Hostname for the HTTP route (required for shared domains)"`
	Path         string            `long:"path" description:"Path for the HTTP route"`
	Port         int               `long:"port" description:"Port for the TCP route"`
	RandomPort   bool              `long:"random-port" description:"Create a random port for the TCP route"`
	usage        interface{}       `usage:"Create an HTTP route:\n      CF_NAME create-route SPACE DOMAIN [--hostname HOSTNAME] [--path PATH]\n\n    Create a TCP route:\n      CF_NAME create-route SPACE DOMAIN (--port PORT | --random-port)\n\nEXAMPLES:\n   CF_NAME create-route my-space example.com                             # example.com\n   CF_NAME create-route my-space example.com --hostname myapp            # myapp.example.com\n   CF_NAME create-route my-space example.com --hostname myapp --path foo # myapp.example.com/foo\n   CF_NAME create-route my-space example.com --port 50000                # example.com:50000"`
}

func (_ CreateRouteCommand) Setup() error {
	return nil
}

func (_ CreateRouteCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
