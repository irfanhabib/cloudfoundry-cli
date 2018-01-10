package v2

import (
	"code.cloudfoundry.org/cli/actor/sharedaction"
	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccversion"
	"code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/command/flag"
	"code.cloudfoundry.org/cli/command/translatableerror"
	"code.cloudfoundry.org/cli/command/v2/shared"
)

type ScaleActor interface {
	CloudControllerAPIVersion() string
}

type ScaleCommand struct {
	RequiredArgs    flag.AppName `positional-args:"yes"`
	ForceRestart    bool         `short:"f" description:"Force restart of app without prompt"`
	NumInstances    int          `short:"i" description:"Number of instances"`
	DiskLimit       string       `short:"k" description:"Disk limit (e.g. 256M, 1024M, 1G)"`
	MemoryLimit     string       `short:"m" description:"Memory limit (e.g. 256M, 1024M, 1G)"`
	ProcessType     string       `long:"process" default:"web" description:"App process to scale"`
	usage           interface{}  `usage:"CF_NAME scale APP_NAME [-i INSTANCES] [-k DISK] [-m MEMORY] [-f]"`
	relatedCommands interface{}  `related_commands:"push"`

	UI          command.UI
	Config      command.Config
	SharedActor command.SharedActor
	Actor       ScaleActor
}

func (cmd *ScaleCommand) Setup(config command.Config, ui command.UI) error {
	cmd.UI = ui
	cmd.Config = config
	cmd.SharedActor = sharedaction.NewActor(config)

	ccClient, uaaClient, err := shared.NewClients(config, ui, true)
	if err != nil {
		return err
	}
	cmd.Actor = v2action.NewActor(ccClient, uaaClient, config)

	return nil
}

func (cmd ScaleCommand) Execute(args []string) error {
	if cmd.ProcessType != "" {
		return translatableerror.MinimumAPIVersionNotMetError{
			Command:        "--process",
			CurrentVersion: cmd.Actor.CloudControllerAPIVersion(),
			MinimumVersion: ccversion.MinVersionV3,
		}
	}

	return translatableerror.UnrefactoredCommandError{}
}
