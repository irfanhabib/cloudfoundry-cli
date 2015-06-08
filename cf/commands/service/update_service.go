package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cloudfoundry/cli/cf/actors/plan_builder"
	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/command_metadata"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/flag_helpers"
	. "github.com/cloudfoundry/cli/cf/i18n"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/cloudfoundry/cli/cf/ui_helpers"
	"github.com/cloudfoundry/cli/json"
	"github.com/codegangsta/cli"
)

type UpdateService struct {
	ui          terminal.UI
	config      core_config.Reader
	serviceRepo api.ServiceRepository
	planBuilder plan_builder.PlanBuilder
}

func NewUpdateService(ui terminal.UI, config core_config.Reader, serviceRepo api.ServiceRepository, planBuilder plan_builder.PlanBuilder) (cmd *UpdateService) {
	return &UpdateService{
		ui:          ui,
		config:      config,
		serviceRepo: serviceRepo,
		planBuilder: planBuilder,
	}
}

func (cmd *UpdateService) Metadata() command_metadata.CommandMetadata {
	baseUsage := T("CF_NAME update-service SERVICE_INSTANCE [-p NEW_PLAN] [-c PARAMETERS_AS_JSON]")
	paramsUsage := T(`   Optionally provide service-specific configuration parameters in a valid JSON object in-line.
   CF_NAME update-service -c '{"name":"value","name":"value"}'

   Optionally provide a file containing service-specific configuration parameters in a valid JSON object. 
   The path to the parameters file can be an absolute or relative path to a file.
   CF_NAME update-service -c PATH_TO_FILE

   Example of valid JSON object:
   {
      "cluster_nodes": {
         "count": 5,
         "memory_mb": 1024
      }
   }`)
	exampleUsage := T(`EXAMPLE:
   CF_NAME update-service mydb -p gold
   CF_NAME update-service mydb -c '{"ram_gb":4}'
   CF_NAME update-service mydb -c ~/workspace/tmp/instance_config.json
	 CF_NAME update-service mydb -t "list,of, tags"`)

	return command_metadata.CommandMetadata{
		Name:        "update-service",
		Description: T("Update a service instance"),
		Usage:       T(strings.Join([]string{baseUsage, paramsUsage, exampleUsage}, "\n\n")),
		Flags: []cli.Flag{
			flag_helpers.NewStringFlag("p", T("Change service plan for a service instance")),
			flag_helpers.NewStringFlag("c", T("Valid JSON object containing service-specific configuration parameters, provided either in-line or in a file. For a list of supported configuration parameters, see documentation for the particular service offering.")),
			flag_helpers.NewStringFlag("t", T("User provided tags")),
		},
	}
}

func (cmd *UpdateService) GetRequirements(requirementsFactory requirements.Factory, c *cli.Context) (reqs []requirements.Requirement, err error) {
	if len(c.Args()) != 1 {
		cmd.ui.FailWithUsage(c)
	}

	reqs = []requirements.Requirement{
		requirementsFactory.NewLoginRequirement(),
		requirementsFactory.NewTargetedSpaceRequirement(),
	}

	return
}

func (cmd *UpdateService) Run(c *cli.Context) {
	planName := c.String("p")
	params := c.String("c")
	tagsList := c.String("t")

	if planName == "" && params == "" && tagsList == "" {
		cmd.ui.Ok()
		cmd.ui.Say(T("No changes were made"))
		return
	}

	serviceInstanceName := c.Args()[0]
	serviceInstance, err := cmd.serviceRepo.FindInstanceByName(serviceInstanceName)
	if err != nil {
		cmd.ui.Failed(err.Error())
	}

	paramsMap, err := json.ParseJsonFromFileOrString(params)
	if err != nil {
		cmd.ui.Failed(T("Invalid configuration provided for -c flag. Please provide a valid JSON object or a file path containing valid JSON."))
	}

	tags := ui_helpers.ParseTags(tagsList)

	var plan models.ServicePlanFields
	if planName != "" {
		cmd.checkUpdateServicePlanApiVersion()
		err, plan = cmd.findPlan(serviceInstance, planName)
		if err != nil {
			cmd.ui.Failed(err.Error())
		}
	}

	cmd.printUpdatingServiceInstanceMessage(serviceInstanceName)

	err = cmd.serviceRepo.UpdateServiceInstance(serviceInstance.Guid, plan.Guid, paramsMap, tags)
	if err != nil {
		cmd.ui.Failed(err.Error())
	}
	err = printSuccessMessageForServiceInstance(serviceInstanceName, cmd.serviceRepo, cmd.ui)
	if err != nil {
		cmd.ui.Failed(err.Error())
	}
}

func (cmd *UpdateService) findPlan(serviceInstance models.ServiceInstance, planName string) (err error, plan models.ServicePlanFields) {
	plans, err := cmd.planBuilder.GetPlansForServiceForOrg(serviceInstance.ServiceOffering.Guid, cmd.config.OrganizationFields().Name)
	if err != nil {
		return
	}

	for _, p := range plans {
		if p.Name == planName {
			plan = p
			return
		}
	}
	err = errors.New(T("Plan does not exist for the {{.ServiceName}} service",
		map[string]interface{}{"ServiceName": serviceInstance.ServiceOffering.Label}))
	return
}

func (cmd *UpdateService) checkUpdateServicePlanApiVersion() {
	if !cmd.config.IsMinApiVersion("2.16.0") {
		cmd.ui.Failed(T("Updating a plan requires API v{{.RequiredCCAPIVersion}} or newer. Your current target is v{{.CurrentCCAPIVersion}}.",
			map[string]interface{}{
				"RequiredCCAPIVersion": "2.16.0",
				"CurrentCCAPIVersion":  cmd.config.ApiVersion(),
			}))
	}
}

func (cmd *UpdateService) printUpdatingServiceInstanceMessage(serviceInstanceName string) {
	cmd.ui.Say(T("Updating service instance {{.ServiceName}} as {{.UserName}}...",
		map[string]interface{}{
			"ServiceName": terminal.EntityNameColor(serviceInstanceName),
			"UserName":    terminal.EntityNameColor(cmd.config.Username()),
		}))
}

func printSuccessMessageForServiceInstance(serviceInstanceName string, serviceRepo api.ServiceRepository, ui terminal.UI) error {
	instance, apiErr := serviceRepo.FindInstanceByName(serviceInstanceName)
	if apiErr != nil {
		return apiErr
	}

	if instance.ServiceInstanceFields.LastOperation.State == "in progress" {
		ui.Ok()
		ui.Say("")
		ui.Say(T("{{.State}} in progress. Use '{{.ServicesCommand}}' or '{{.ServiceCommand}}' to check operation status.",
			map[string]interface{}{
				"State":           strings.Title(instance.ServiceInstanceFields.LastOperation.Type),
				"ServicesCommand": terminal.CommandColor("cf services"),
				"ServiceCommand":  terminal.CommandColor(fmt.Sprintf("cf service %s", serviceInstanceName)),
			}))
	} else {
		ui.Ok()
	}

	return nil
}
