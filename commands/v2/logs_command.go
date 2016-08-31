package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type LogsCommand struct {
	RequiredArgs flags.AppName `positional-args:"yes"`
	Recent       bool          `long:"recent" description:"Dump recent logs instead of tailing"`
	usage        interface{}   `usage:"CF_NAME logs APP_NAME"`
}

func (_ LogsCommand) Setup() error {
	return nil
}

func (_ LogsCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
