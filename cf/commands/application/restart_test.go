package application_test

import (
	"github.com/cloudfoundry/cli/cf/commands/application/applicationfakes"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/trace/tracefakes"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("restart command", func() {
	var (
		ui                  *testterm.FakeUI
		requirementsFactory *testreq.FakeReqFactory
		starter             *applicationfakes.FakeApplicationStarter
		stopper             *applicationfakes.FakeApplicationStopper
		config              coreconfig.Repository
		app                 models.Application
		originalStop        commandregistry.Command
		originalStart       commandregistry.Command
		deps                commandregistry.Dependency
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.Ui = ui
		deps.Config = config

		//inject fake 'stopper and starter' into registry
		commandregistry.Register(starter)
		commandregistry.Register(stopper)

		commandregistry.Commands.SetCommand(commandregistry.Commands.FindCommand("restart").SetDependency(deps, pluginCall))
	}

	runCommand := func(args ...string) bool {
		return testcmd.RunCliCommand("restart", args, requirementsFactory, updateCommandDependency, false)
	}

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		deps = commandregistry.NewDependency(new(tracefakes.FakePrinter))
		requirementsFactory = &testreq.FakeReqFactory{}
		starter = new(applicationfakes.FakeApplicationStarter)
		stopper = new(applicationfakes.FakeApplicationStopper)
		config = testconfig.NewRepositoryWithDefaults()

		app = models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"

		//save original command and restore later
		originalStart = commandregistry.Commands.FindCommand("start")
		originalStop = commandregistry.Commands.FindCommand("stop")

		//setup fakes to correctly interact with commandregistry
		starter.SetDependencyStub = func(_ commandregistry.Dependency, _ bool) commandregistry.Command {
			return starter
		}
		starter.MetaDataReturns(commandregistry.CommandMetadata{Name: "start"})

		stopper.SetDependencyStub = func(_ commandregistry.Dependency, _ bool) commandregistry.Command {
			return stopper
		}
		stopper.MetaDataReturns(commandregistry.CommandMetadata{Name: "stop"})
	})

	AfterEach(func() {
		commandregistry.Register(originalStart)
		commandregistry.Register(originalStop)
	})

	Describe("requirements", func() {
		It("fails with usage when not provided exactly one arg", func() {
			requirementsFactory.LoginSuccess = true
			runCommand()
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Incorrect Usage", "Requires an argument"},
			))
		})

		It("fails when not logged in", func() {
			requirementsFactory.Application = app
			requirementsFactory.TargetedSpaceSuccess = true

			Expect(runCommand()).To(BeFalse())
		})

		It("fails when a space is not targeted", func() {
			requirementsFactory.Application = app
			requirementsFactory.LoginSuccess = true

			Expect(runCommand()).To(BeFalse())
		})
	})

	Context("when logged in, targeting a space, and an app name is provided", func() {
		BeforeEach(func() {
			requirementsFactory.Application = app
			requirementsFactory.LoginSuccess = true
			requirementsFactory.TargetedSpaceSuccess = true

			stopper.ApplicationStopReturns(app, nil)
		})

		It("restarts the given app", func() {
			runCommand("my-app")

			application, orgName, spaceName := stopper.ApplicationStopArgsForCall(0)
			Expect(application).To(Equal(app))
			Expect(orgName).To(Equal(config.OrganizationFields().Name))
			Expect(spaceName).To(Equal(config.SpaceFields().Name))

			application, orgName, spaceName = starter.ApplicationStartArgsForCall(0)
			Expect(application).To(Equal(app))
			Expect(orgName).To(Equal(config.OrganizationFields().Name))
			Expect(spaceName).To(Equal(config.SpaceFields().Name))

			Expect(requirementsFactory.ApplicationName).To(Equal("my-app"))
		})
	})
})
