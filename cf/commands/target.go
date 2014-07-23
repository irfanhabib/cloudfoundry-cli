package commands

import (
	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/api/spaces"
	"github.com/cloudfoundry/cli/cf/command_metadata"
	"github.com/cloudfoundry/cli/cf/configuration"
	"github.com/cloudfoundry/cli/cf/errors"
	"github.com/cloudfoundry/cli/cf/flag_helpers"
	. "github.com/cloudfoundry/cli/cf/i18n"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/codegangsta/cli"
)

type Target struct {
	ui        terminal.UI
	config    configuration.ReadWriter
	orgRepo   api.OrganizationRepository
	spaceRepo spaces.SpaceRepository
}

func NewTarget(ui terminal.UI,
	config configuration.ReadWriter,
	orgRepo api.OrganizationRepository,
	spaceRepo spaces.SpaceRepository) (cmd Target) {

	cmd.ui = ui
	cmd.config = config
	cmd.orgRepo = orgRepo
	cmd.spaceRepo = spaceRepo

	return
}

func (cmd Target) Metadata() command_metadata.CommandMetadata {
	return command_metadata.CommandMetadata{
		Name:        "target",
		ShortName:   "t",
		Description: T("Set or view the targeted org or space"),
		Usage:       T("CF_NAME target [-o ORG] [-s SPACE]"),
		Flags: []cli.Flag{
			flag_helpers.NewStringFlag("o", T("organization")),
			flag_helpers.NewStringFlag("s", T("space")),
		},
	}
}

func (cmd Target) GetRequirements(requirementsFactory requirements.Factory, c *cli.Context) (reqs []requirements.Requirement, err error) {
	if len(c.Args()) != 0 {
		err = errors.New(T("incorrect usage"))
		cmd.ui.FailWithUsage(c)
		return
	}

	if c.String("o") != "" || c.String("s") != "" {
		reqs = append(reqs, requirementsFactory.NewLoginRequirement())
	}

	return
}

func (cmd Target) Run(c *cli.Context) {
	orgName := c.String("o")
	spaceName := c.String("s")

	if orgName != "" {
		err := cmd.setOrganization(orgName)
		if err != nil {
			cmd.ui.Failed(err.Error())
		}
	}

	if spaceName != "" {
		err := cmd.setSpace(spaceName)
		if err != nil {
			cmd.ui.Failed(err.Error())
		}
	}

	cmd.ui.ShowConfiguration(cmd.config)
	if !cmd.config.IsLoggedIn() {
		cmd.ui.PanicQuietly()
	}
	return
}

func (cmd Target) setOrganization(orgName string) error {
	// setting an org necessarily invalidates any space you had previously targeted
	cmd.config.SetOrganizationFields(models.OrganizationFields{})
	cmd.config.SetSpaceFields(models.SpaceFields{})

	org, apiErr := cmd.orgRepo.FindByName(orgName)
	if apiErr != nil {
		return errors.NewWithFmt(T("Could not target org.\n{{.ApiErr}}",
			map[string]interface{}{"ApiErr": apiErr.Error()}))
	}

	cmd.config.SetOrganizationFields(org.OrganizationFields)
	return nil
}

func (cmd Target) setSpace(spaceName string) error {
	cmd.config.SetSpaceFields(models.SpaceFields{})

	if !cmd.config.HasOrganization() {
		return errors.New(T("An org must be targeted before targeting a space"))
	}

	space, apiErr := cmd.spaceRepo.FindByName(spaceName)
	if apiErr != nil {
		return errors.NewWithFmt(T("Unable to access space {{.SpaceName}}.\n{{.ApiErr}}",
			map[string]interface{}{"SpaceName": spaceName, "ApiErr": apiErr.Error()}))
	}

	cmd.config.SetSpaceFields(space.SpaceFields)
	return nil
}
