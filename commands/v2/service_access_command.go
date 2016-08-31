package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
)

type ServiceAccessCommand struct {
	Broker       string `short:"b" description:"Access for plans of a particular broker"`
	Service      string `short:"e" description:"Access for service name of a particular service offering"`
	Organization string `short:"o" description:"Plans accessible by a particular organization"`
}

func (_ ServiceAccessCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
