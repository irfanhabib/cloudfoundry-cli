package commands

import (
	"github.com/cloudfoundry/cli/cf/command"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"
	"github.com/codegangsta/cli"
)

var CommandDidPassRequirements bool

func RunCommand(cmd command.Command, ctxt *cli.Context, requirementsFactory *testreq.FakeReqFactory) bool {
	defer func() {
		errMsg := recover()

		if errMsg != nil && errMsg != testterm.FailedWasCalled {
			panic(errMsg)
		}
	}()

	CommandDidPassRequirements = false

	requirements, err := cmd.GetRequirements(requirementsFactory, ctxt)
	if err != nil {
		return false
	}

	for _, requirement := range requirements {
		success := requirement.Execute()
		if !success {
			return false
		}
	}

	CommandDidPassRequirements = true
	cmd.Run(ctxt)

	return true
}
