package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type RunningSecurityGroupsCommand struct {
	usage interface{} `usage:"CF_NAME running-security-groups"`
}

func (_ RunningSecurityGroupsCommand) Setup(config commands.Config) error {
	return nil
}

func (_ RunningSecurityGroupsCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
