package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type UpdateServiceAuthTokenCommand struct {
	RequiredArgs flags.ServiceAuthTokenArgs `positional-args:"yes"`
}

func (_ UpdateServiceAuthTokenCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
