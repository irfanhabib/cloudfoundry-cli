package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type SetSpaceRoleCommand struct {
	RequiredArgs flags.SetSpaceRoleArgs `positional-args:"yes"`
	usage        interface{}            `usage:"CF_NAME set-space-role USERNAME ORG SPACE ROLE\n\nROLES:\n    'SpaceManager' - Invite and manage users, and enable features for a given space\n    'SpaceDeveloper' - Create and manage apps and services, and see logs and reports\n    'SpaceAuditor' - View logs, reports, and settings on this space"`
}

func (_ SetSpaceRoleCommand) Setup() error {
	return nil
}

func (_ SetSpaceRoleCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
