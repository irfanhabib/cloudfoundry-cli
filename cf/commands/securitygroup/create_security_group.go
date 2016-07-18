package securitygroup

import (
	"github.com/cloudfoundry/cli/cf/flags"
	. "github.com/cloudfoundry/cli/cf/i18n"

	"github.com/cloudfoundry/cli/cf/api/securitygroups"
	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/errors"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/cloudfoundry/cli/utils/json"
)

type CreateSecurityGroup struct {
	ui                terminal.UI
	securityGroupRepo securitygroups.SecurityGroupRepo
	configRepo        coreconfig.Reader
}

func init() {
	commandregistry.Register(&CreateSecurityGroup{})
}

func (cmd *CreateSecurityGroup) MetaData() commandregistry.CommandMetadata {
	primaryUsage := T("CF_NAME create-security-group SECURITY_GROUP PATH_TO_JSON_RULES_FILE")
	secondaryUsage := T(`   The provided path can be an absolute or relative path to a file.  The file should have
   a single array with JSON objects inside describing the rules.  The JSON Base Object is 
   omitted and only the square brackets and associated child object are required in the file.  

   Valid json file example:
   [
     {
       "protocol": "tcp",
       "destination": "10.244.1.18",
       "ports": "3306"
     }
   ]`)

	return commandregistry.CommandMetadata{
		Name:        "create-security-group",
		Description: T("Create a security group"),
		Usage: []string{
			primaryUsage,
			"\n\n",
			secondaryUsage,
		},
	}
}

func (cmd *CreateSecurityGroup) Requirements(requirementsFactory requirements.Factory, fc flags.FlagContext) []requirements.Requirement {
	if len(fc.Args()) != 2 {
		cmd.ui.Failed(T("Incorrect Usage. Requires SECURITY_GROUP and PATH_TO_JSON_RULES_FILE as arguments\n\n") + commandregistry.Commands.CommandUsage("create-security-group"))
	}

	reqs := []requirements.Requirement{
		requirementsFactory.NewLoginRequirement(),
	}

	return reqs
}

func (cmd *CreateSecurityGroup) SetDependency(deps commandregistry.Dependency, pluginCall bool) commandregistry.Command {
	cmd.ui = deps.UI
	cmd.configRepo = deps.Config
	cmd.securityGroupRepo = deps.RepoLocator.GetSecurityGroupRepository()
	return cmd
}

func (cmd *CreateSecurityGroup) Execute(context flags.FlagContext) error {
	name := context.Args()[0]
	pathToJSONFile := context.Args()[1]
	rules, err := json.ParseJSONArray(pathToJSONFile)
	if err != nil {
		return errors.New(T(`Incorrect json format: file: {{.JSONFile}}
		
Valid json file example:
[
  {
    "protocol": "tcp",
    "destination": "10.244.1.18",
    "ports": "3306"
  }
]`, map[string]interface{}{"JSONFile": pathToJSONFile}))
	}

	cmd.ui.Say(T("Creating security group {{.security_group}} as {{.username}}",
		map[string]interface{}{
			"security_group": terminal.EntityNameColor(name),
			"username":       terminal.EntityNameColor(cmd.configRepo.Username()),
		}))

	err = cmd.securityGroupRepo.Create(name, rules)

	httpErr, ok := err.(errors.HTTPError)
	if ok && httpErr.ErrorCode() == errors.SecurityGroupNameTaken {
		cmd.ui.Ok()
		cmd.ui.Warn(T("Security group {{.security_group}} {{.error_message}}",
			map[string]interface{}{
				"security_group": terminal.EntityNameColor(name),
				"error_message":  terminal.WarningColor(T("already exists")),
			}))
		return nil
	}

	if err != nil {
		return err
	}

	cmd.ui.Ok()
	return nil
}
