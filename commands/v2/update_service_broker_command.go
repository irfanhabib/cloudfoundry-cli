package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
	"code.cloudfoundry.org/cli/commands/flags"
)

type UpdateServiceBrokerCommand struct {
	RequiredArgs flags.ServiceBrokerArgs `positional-args:"yes"`
	usage        interface{}             `usage:"CF_NAME update-service-broker SERVICE_BROKER USERNAME PASSWORD URL"`
}

func (_ UpdateServiceBrokerCommand) Setup(config commands.Config) error {
	return nil
}

func (_ UpdateServiceBrokerCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
