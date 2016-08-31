package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type QuotaCommand struct {
	RequiredArgs flags.Quota `positional-args:"yes"`
	usage        interface{} `usage:"CF_NAME quota QUOTA"`
}

func (_ QuotaCommand) Setup() error {
	return nil
}

func (_ QuotaCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
