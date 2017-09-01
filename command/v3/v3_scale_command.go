package v3

import (
	"strconv"

	"github.com/cloudfoundry/bytefmt"

	"code.cloudfoundry.org/cli/actor/sharedaction"
	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/command/flag"
	"code.cloudfoundry.org/cli/command/translatableerror"
	"code.cloudfoundry.org/cli/command/v3/shared"
)

//go:generate counterfeiter . V3ScaleActor

type V3ScaleActor interface {
	shared.V3AppSummaryActor

	CloudControllerAPIVersion() string
	GetApplicationByNameAndSpace(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error)
	GetProcessByApplicationAndProcessType(appGUID string, processType string) (v3action.Process, v3action.Warnings, error)
	ScaleProcessByApplication(appGUID string, process v3action.Process) (v3action.Warnings, error)
	StopApplication(appGUID string) (v3action.Warnings, error)
	StartApplication(appGUID string) (v3action.Application, v3action.Warnings, error)
	PollStart(appGUID string, warnings chan<- v3action.Warnings) error
}

type V3ScaleCommand struct {
	RequiredArgs        flag.AppName   `positional-args:"yes"`
	Force               bool           `short:"f" description:"Force restart of app without prompt"`
	ProcessType         string         `long:"process" default:"web" description:"App process to scale"`
	Instances           flag.Instances `short:"i" required:"false" description:"Number of instances"`
	DiskLimit           flag.Megabytes `short:"k" required:"false" description:"Disk limit (e.g. 256M, 1024M, 1G)"`
	MemoryLimit         flag.Megabytes `short:"m" required:"false" description:"Memory limit (e.g. 256M, 1024M, 1G)"`
	usage               interface{}    `usage:"CF_NAME v3-scale APP_NAME [--process PROCESS] [-i INSTANCES] [-k DISK] [-m MEMORY]"`
	relatedCommands     interface{}    `related_commands:"v3-push"`
	envCFStartupTimeout interface{}    `environmentName:"CF_STARTUP_TIMEOUT" environmentDescription:"Max wait time for app instance startup, in minutes" environmentDefault:"5"`

	UI          command.UI
	Config      command.Config
	Actor       V3ScaleActor
	SharedActor command.SharedActor
}

func (cmd *V3ScaleCommand) Setup(config command.Config, ui command.UI) error {
	cmd.UI = ui
	cmd.Config = config
	cmd.SharedActor = sharedaction.NewActor()

	ccClient, _, err := shared.NewClients(config, ui, true)
	if err != nil {
		return err
	}
	cmd.Actor = v3action.NewActor(ccClient, config)

	return nil
}

func (cmd V3ScaleCommand) Execute(args []string) error {
	cmd.UI.DisplayText(command.ExperimentalWarning)
	cmd.UI.DisplayNewline()

	err := command.MinimumAPIVersionCheck(cmd.Actor.CloudControllerAPIVersion(), command.MinVersionV3)
	if err != nil {
		return err
	}

	err = cmd.SharedActor.CheckTarget(cmd.Config, true, true)
	if err != nil {
		return shared.HandleError(err)
	}

	user, err := cmd.Config.CurrentUser()
	if err != nil {
		return err
	}

	app, warnings, err := cmd.Actor.GetApplicationByNameAndSpace(cmd.RequiredArgs.AppName, cmd.Config.TargetedSpace().GUID)
	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return shared.HandleError(err)
	}

	if !cmd.Instances.IsSet && !cmd.DiskLimit.IsSet && !cmd.MemoryLimit.IsSet {
		cmd.UI.DisplayTextWithFlavor("Showing current scale of process {{.Process}} of app {{.AppName}} in org {{.OrgName}} / space {{.SpaceName}} as {{.Username}}...", map[string]interface{}{
			"Process":   cmd.ProcessType,
			"AppName":   cmd.RequiredArgs.AppName,
			"OrgName":   cmd.Config.TargetedOrganization().Name,
			"SpaceName": cmd.Config.TargetedSpace().Name,
			"Username":  user.Name,
		})

		return cmd.getAndDisplayProcess(app.GUID)
	}

	err = cmd.scaleProcess(app.GUID, user.Name)
	if err != nil {
		return shared.HandleError(err)
	}

	pollWarnings := make(chan v3action.Warnings)
	done := make(chan bool)
	go func() {
		for {
			select {
			case message := <-pollWarnings:
				cmd.UI.DisplayWarnings(message)
			case <-done:
				return
			}
		}
	}()

	err = cmd.Actor.PollStart(app.GUID, pollWarnings)
	done <- true

	if err != nil {
		if _, ok := err.(v3action.StartupTimeoutError); ok {
			return translatableerror.StartupTimeoutError{
				AppName:    cmd.RequiredArgs.AppName,
				BinaryName: cmd.Config.BinaryName(),
			}
		} else {
			return shared.HandleError(err)
		}
	}

	return cmd.getAndDisplayProcess(app.GUID)
}

func (cmd V3ScaleCommand) getAndDisplayProcess(appGUID string) error {
	cmd.UI.DisplayNewline()
	process, warnings, err := cmd.Actor.GetProcessByApplicationAndProcessType(appGUID, cmd.ProcessType)
	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return shared.HandleError(err)
	}

	keyValueTable := [][]string{
		{cmd.UI.TranslateText("memory:"), bytefmt.ByteSize(process.MemoryInMB.Value * bytefmt.MEGABYTE)},
		{cmd.UI.TranslateText("disk:"), bytefmt.ByteSize(process.DiskInMB.Value * bytefmt.MEGABYTE)},
		{cmd.UI.TranslateText("instances:"), strconv.Itoa(process.Instances.Value)},
	}

	cmd.UI.DisplayKeyValueTable("", keyValueTable, 3)

	return nil
}

func (cmd V3ScaleCommand) scaleProcess(appGUID string, username string) error {
	cmd.UI.DisplayTextWithFlavor("Scaling process {{.Process}} of app {{.AppName}} in org {{.OrgName}} / space {{.SpaceName}} as {{.Username}}...", map[string]interface{}{
		"Process":   cmd.ProcessType,
		"AppName":   cmd.RequiredArgs.AppName,
		"OrgName":   cmd.Config.TargetedOrganization().Name,
		"SpaceName": cmd.Config.TargetedSpace().Name,
		"Username":  username,
	})

	shouldRestart := cmd.DiskLimit.IsSet || cmd.MemoryLimit.IsSet
	if shouldRestart && !cmd.Force {
		cmd.UI.DisplayNewline()
		shouldScale, err := cmd.UI.DisplayBoolPrompt(
			false,
			"This will cause the app to restart. Are you sure you want to scale {{.AppName}}?",
			map[string]interface{}{"AppName": cmd.RequiredArgs.AppName})
		if err != nil {
			return err
		}

		if !shouldScale {
			cmd.UI.DisplayText("Scaling cancelled")
			return nil
		}
	}

	warnings, err := cmd.Actor.ScaleProcessByApplication(appGUID, v3action.Process{
		Type:       cmd.ProcessType,
		Instances:  cmd.Instances.NullInt,
		MemoryInMB: cmd.MemoryLimit.NullUint64,
		DiskInMB:   cmd.DiskLimit.NullUint64,
	})
	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return err
	}

	if shouldRestart {
		err := cmd.restartApplication(appGUID, username)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cmd V3ScaleCommand) restartApplication(appGUID string, username string) error {
	cmd.UI.DisplayNewline()
	cmd.UI.DisplayTextWithFlavor("Stopping app {{.AppName}} in org {{.OrgName}} / space {{.SpaceName}} as {{.Username}}...", map[string]interface{}{
		"AppName":   cmd.RequiredArgs.AppName,
		"OrgName":   cmd.Config.TargetedOrganization().Name,
		"SpaceName": cmd.Config.TargetedSpace().Name,
		"Username":  username,
	})

	warnings, err := cmd.Actor.StopApplication(appGUID)
	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return err
	}

	cmd.UI.DisplayNewline()
	cmd.UI.DisplayTextWithFlavor("Starting app {{.AppName}} in org {{.OrgName}} / space {{.SpaceName}} as {{.Username}}...", map[string]interface{}{
		"AppName":   cmd.RequiredArgs.AppName,
		"OrgName":   cmd.Config.TargetedOrganization().Name,
		"SpaceName": cmd.Config.TargetedSpace().Name,
		"Username":  username,
	})

	_, warnings, err = cmd.Actor.StartApplication(appGUID)
	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return err
	}

	return nil
}
