package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type FeatureFlagsCommand struct {
	usage interface{} `usage:"CF_NAME feature-flags"`
}

func (_ FeatureFlagsCommand) Setup(config commands.Config) error {
	return nil
}

func (_ FeatureFlagsCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
