package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type SpaceSSHAllowedCommand struct {
	RequiredArgs flags.Space `positional-args:"yes"`
	usage        interface{} `usage:"CF_NAME space-ssh-allowed SPACE_NAME"`
}

func (_ SpaceSSHAllowedCommand) Setup() error {
	return nil
}

func (_ SpaceSSHAllowedCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
