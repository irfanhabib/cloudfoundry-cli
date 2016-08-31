package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type UnsetEnvCommand struct {
	usage interface{} `usage:"CF_NAME unset-env APP_NAME ENV_VAR_NAME"`
}

func (_ UnsetEnvCommand) Setup(config commands.Config) error {
	return nil
}

func (_ UnsetEnvCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
