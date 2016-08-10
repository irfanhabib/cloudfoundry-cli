package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type RenameBuildpackCommand struct {
	RequiredArgs flags.RenameBuildpackArgs `positional-args:"yes"`
	usage        interface{}               `usage:"CF_NAME rename-buildpack BUILDPACK_NAME NEW_BUILDPACK_NAME"`
}

func (_ RenameBuildpackCommand) Setup() error {
	return nil
}

func (_ RenameBuildpackCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
