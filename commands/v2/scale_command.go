package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
	"code.cloudfoundry.org/cli/commands/flags"
)

type ScaleCommand struct {
	RequiredArgs    flags.AppName `positional-args:"yes"`
	ForceRestart    bool          `short:"f" description:"Force restart of app without prompt"`
	NumInstances    int           `short:"i" description:"Number of instances"`
	DiskLimit       string        `short:"k" description:"Disk limit (e.g. 256M, 1024M, 1G)"`
	MemoryLimit     string        `short:"m" description:"Memory limit (e.g. 256M, 1024M, 1G)"`
	usage           interface{}   `usage:"CF_NAME scale APP_NAME [-i INSTANCES] [-k DISK] [-m MEMORY] [-f]"`
	relatedCommands interface{}   `related_commands:"push"`
}

func (_ ScaleCommand) Setup(config commands.Config, ui commands.UI) error {
	return nil
}

func (_ ScaleCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
