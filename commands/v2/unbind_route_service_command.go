package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type UnbindRouteServiceCommand struct {
	RequiredArgs flags.RouteServiceArgs `positional-args:"yes"`
	Force        bool                   `short:"f" description:"Force unbinding without confirmation"`
	Hostname     string                 `long:"hostname" short:"n" description:"Hostname used in combination with DOMAIN to specify the route to bind"`
	Path         string                 `long:"path" description:"Path for the HTTP route"`
	usage        interface{}            `usage:"CF_NAME unbind-route-service DOMAIN SERVICE_INSTANCE [--hostname HOSTNAME] [--path PATH] [-f]\n\nEXAMPLES:\n    CF_NAME unbind-route-service example.com myratelimiter --hostname myapp --path foo"`
}

func (_ UnbindRouteServiceCommand) Setup() error {
	return nil
}

func (_ UnbindRouteServiceCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
