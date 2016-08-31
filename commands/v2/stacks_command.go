package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type StacksCommand struct {
	usage interface{} `usage:"CF_NAME stacks"`
}

func (_ StacksCommand) Setup(config commands.Config) error {
	return nil
}

func (_ StacksCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
