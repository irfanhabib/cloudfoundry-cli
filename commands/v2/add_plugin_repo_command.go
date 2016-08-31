package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type AddPluginRepoCommand struct {
	RequiredArgs flags.AddPluginRepoArgs `positional-args:"yes"`
	usage        interface{}             `usage:"CF_NAME add-plugin-repo REPO_NAME URL\n\nEXAMPLES:\n    CF_NAME add-plugin-repo PrivateRepo https://myprivaterepo.com/repo/"`
}

func (_ AddPluginRepoCommand) Setup() error {
	return nil
}

func (_ AddPluginRepoCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
