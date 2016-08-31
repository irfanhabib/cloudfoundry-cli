package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type CreateSpaceQuotaCommand struct {
	RequiredArgs                flags.SpaceQuota `positional-args:"yes"`
	AllowPaidServicePlans       bool             `long:"allow-paid-service-plans" description:"Can provision instances of paid service plans (Default: disallowed)"`
	IndividualAppInstanceMemory string           `short:"i" description:"Maximum amount of memory an application instance can have (e.g. 1024M, 1G, 10G). -1 represents an unlimited amount. (Default: unlimited)"`
	TotalMemory                 string           `short:"m" description:"Total amount of memory a space can have (e.g. 1024M, 1G, 10G)"`
	NumRoutes                   int              `short:"r" description:"Total number of routes"`
	NumServiceInstances         int              `short:"s" description:"Total number of service instances"`
	NumAppInstances             int              `short:"a" description:"Total number of application instances. -1 represents an unlimited amount. (Default: unlimited)"`
	ReservedRoutePorts          int              `long:"reserved-route-ports" description:"Maximum number of routes that may be created with reserved ports (Default: 0)"`
}

func (_ CreateSpaceQuotaCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
