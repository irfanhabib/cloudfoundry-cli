package fake_command

import (
	"github.com/cloudfoundry/cli/cf/command_registry"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/cloudfoundry/cli/flags"
)

type FakeCommand1 struct {
	Data string
	req  fakeReq
}

func init() {
	command_registry.Register(FakeCommand1{Data: "FakeCommand1 data", req: fakeReq{}})
}

func (cmd FakeCommand1) MetaData() command_registry.CommandMetadata {
	return command_registry.CommandMetadata{
		Name:        "fake-non-codegangsta-command",
		Description: "Description for fake-command",
		Usage:       "Usage of fake-command",
	}
}

func (cmd FakeCommand1) Requirements(_ requirements.Factory, _ flags.FlagContext) (reqs []requirements.Requirement, err error) {
	return []requirements.Requirement{cmd.req}, nil
}

func (cmd FakeCommand1) SetDependency(deps command_registry.Dependency) command_registry.Command {
	cmd.req.ui = deps.Ui
	return cmd
}

func (cmd FakeCommand1) Execute(c flags.FlagContext) {
}

type fakeReq struct {
	ui terminal.UI
}

func (f fakeReq) Execute() bool {
	f.ui.Say("Requirement executed")
	return true
}
