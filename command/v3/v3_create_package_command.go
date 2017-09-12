package v3

import (
	"net/http"

	"code.cloudfoundry.org/cli/actor/sharedaction"
	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccerror"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccversion"
	"code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/command/flag"
	"code.cloudfoundry.org/cli/command/translatableerror"
	"code.cloudfoundry.org/cli/command/v3/shared"
)

//go:generate counterfeiter . V3CreatePackageActor

type V3CreatePackageActor interface {
	CloudControllerAPIVersion() string
	CreatePackageByApplicationNameAndSpace(appName string, spaceGUID string, bitsPath string, dockerImageCredentials v3action.DockerImageCredentials) (v3action.Package, v3action.Warnings, error)
}

type V3CreatePackageCommand struct {
	RequiredArgs flag.AppName     `positional-args:"yes"`
	DockerImage  flag.DockerImage `long:"docker-image" short:"o" description:"Docker-image to be used (e.g. user/docker-image-name)"`
	usage        interface{}      `usage:"CF_NAME v3-create-package APP_NAME [--docker-image [REGISTRY_HOST:PORT/]IMAGE[:TAG]]"`

	UI          command.UI
	Config      command.Config
	SharedActor command.SharedActor
	Actor       V3CreatePackageActor

	PackageDisplayer shared.PackageDisplayer
}

func (cmd *V3CreatePackageCommand) Setup(config command.Config, ui command.UI) error {
	cmd.UI = ui
	cmd.Config = config
	cmd.SharedActor = sharedaction.NewActor()

	client, _, err := shared.NewClients(config, ui, true)
	if err != nil {
		if v3Err, ok := err.(ccerror.V3UnexpectedResponseError); ok && v3Err.ResponseCode == http.StatusNotFound {
			return translatableerror.MinimumAPIVersionNotMetError{MinimumVersion: ccversion.MinVersionV3}
		}

		return err
	}
	cmd.Actor = v3action.NewActor(client, config)

	cmd.PackageDisplayer = shared.NewPackageDisplayer(cmd.UI, cmd.Config)

	return nil
}

func (cmd V3CreatePackageCommand) Execute(args []string) error {
	cmd.UI.DisplayText(command.ExperimentalWarning)
	cmd.UI.DisplayNewline()

	err := command.MinimumAPIVersionCheck(cmd.Actor.CloudControllerAPIVersion(), ccversion.MinVersionV3)
	if err != nil {
		return err
	}

	err = cmd.SharedActor.CheckTarget(cmd.Config, true, true)
	if err != nil {
		return shared.HandleError(err)
	}

	isDockerImage := (cmd.DockerImage.Path != "")
	err = cmd.PackageDisplayer.DisplaySetupMessage(cmd.RequiredArgs.AppName, isDockerImage)
	if err != nil {
		return shared.HandleError(err)
	}

	pkg, warnings, err := cmd.Actor.CreatePackageByApplicationNameAndSpace(cmd.RequiredArgs.AppName, cmd.Config.TargetedSpace().GUID, "", v3action.DockerImageCredentials{Path: cmd.DockerImage.Path})

	cmd.UI.DisplayWarnings(warnings)
	if err != nil {
		return shared.HandleError(err)
	}

	cmd.UI.DisplayText("package guid: {{.PackageGuid}}", map[string]interface{}{
		"PackageGuid": pkg.GUID,
	})
	cmd.UI.DisplayOK()

	return nil
}
