package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type UnsharePrivateDomainCommand struct {
	RequiredArgs flags.OrgDomain `positional-args:"yes"`
	usage        interface{}     `usage:"CF_NAME unshare-private-domain ORG DOMAIN"`
}

func (_ UnsharePrivateDomainCommand) Setup() error {
	return nil
}

func (_ UnsharePrivateDomainCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
