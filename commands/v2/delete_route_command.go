package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
	"code.cloudfoundry.org/cli/commands/flags"
)

type DeleteRouteCommand struct {
	RequiredArgs flags.Domain `positional-args:"yes"`
	Force        bool         `short:"f" description:"Force deletion without confirmation"`
	Hostname     string       `long:"hostname" short:"n" description:"Hostname used to identify the HTTP route"`
	Path         string       `long:"path" description:"Path used to identify the HTTP route"`
	Port         int          `long:"port" description:"Port used to identify the TCP route"`
	usage        interface{}  `usage:"Delete an HTTP route:\n      CF_NAME delete-route DOMAIN [--hostname HOSTNAME] [--path PATH] [-f]\n\n   Delete a TCP route:\n      CF_NAME delete-route DOMAIN --port PORT [-f]\n\nEXAMPLES:\n   CF_NAME delete-route example.com                              # example.com\n   CF_NAME delete-route example.com --hostname myhost            # myhost.example.com\n   CF_NAME delete-route example.com --hostname myhost --path foo # myhost.example.com/foo\n   CF_NAME delete-route example.com --port 50000                 # example.com:50000"`
}

func (_ DeleteRouteCommand) Setup(config commands.Config) error {
	return nil
}

func (_ DeleteRouteCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
