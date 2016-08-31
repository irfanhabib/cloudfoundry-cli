package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
	"code.cloudfoundry.org/cli/commands/flags"
)

type StackCommand struct {
	RequiredArgs flags.StackName `positional-args:"yes"`
	GUID         bool            `long:"guid" description:"Retrieve and display the given stack's guid. All other output for the stack is suppressed."`
	usage        interface{}     `usage:"CF_NAME stack STACK_NAME"`
}

func (_ StackCommand) Setup(config commands.Config) error {
	return nil
}

func (_ StackCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
