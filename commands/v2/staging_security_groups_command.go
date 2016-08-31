package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type StagingSecurityGroupsCommand struct {
	usage interface{} `usage:"CF_NAME staging-security-groups"`
}

func (_ StagingSecurityGroupsCommand) Setup(config commands.Config) error {
	return nil
}

func (_ StagingSecurityGroupsCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
