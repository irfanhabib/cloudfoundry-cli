package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type CreateOrgCommand struct {
	RequiredArgs flags.Organization `positional-args:"yes"`
	Quota        string             `short:"q" description:"Quota to assign to the newly created org (excluding this option results in assignment of default quota)"`
	usage        interface{}        `usage:"CF_NAME create-org ORG"`
}

func (_ CreateOrgCommand) Setup() error {
	return nil
}

func (_ CreateOrgCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
