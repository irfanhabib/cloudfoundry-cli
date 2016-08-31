package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands"
)

type ServiceBrokersCommand struct {
	usage interface{} `usage:"CF_NAME service-brokers"`
}

func (_ ServiceBrokersCommand) Setup(config commands.Config) error {
	return nil
}

func (_ ServiceBrokersCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
