package commands_test

import (
	"errors"

	"github.com/cloudfoundry/cli/cf/api/stacks/stacksfakes"
	"github.com/cloudfoundry/cli/cf/models"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
)

var _ = Describe("stack command", func() {
	var (
		ui                  *testterm.FakeUI
		config              coreconfig.Repository
		repo                *stacksfakes.FakeStackRepository
		requirementsFactory *testreq.FakeReqFactory
		deps                commandregistry.Dependency
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.Ui = ui
		deps.Config = config
		deps.RepoLocator = deps.RepoLocator.SetStackRepository(repo)
		commandregistry.Commands.SetCommand(commandregistry.Commands.FindCommand("stack").SetDependency(deps, pluginCall))
	}

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		config = testconfig.NewRepositoryWithDefaults()
		requirementsFactory = &testreq.FakeReqFactory{LoginSuccess: true}
		repo = new(stacksfakes.FakeStackRepository)
	})

	Describe("login requirements", func() {
		It("fails if the user is not logged in", func() {
			requirementsFactory.LoginSuccess = false

			Expect(testcmd.RunCliCommand("stack", []string{}, requirementsFactory, updateCommandDependency, false)).To(BeFalse())
		})

		It("fails with usage when not provided exactly one arg", func() {
			requirementsFactory.LoginSuccess = true
			Expect(testcmd.RunCliCommand("stack", []string{}, requirementsFactory, updateCommandDependency, false)).To(BeFalse())
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"FAILED"},
				[]string{"Incorrect Usage.", "Requires stack name as argument"},
			))
		})
	})

	It("returns the stack guid when '--guid' flag is provided", func() {
		stack1 := models.Stack{
			Name:        "Stack-1",
			Description: "Stack 1 Description",
			Guid:        "Stack-1-GUID",
		}

		repo.FindByNameReturns(stack1, nil)

		testcmd.RunCliCommand("stack", []string{"Stack-1", "--guid"}, requirementsFactory, updateCommandDependency, false)

		Expect(len(ui.Outputs)).To(Equal(1))
		Expect(ui.Outputs[0]).To(Equal("Stack-1-GUID"))
	})

	It("returns the empty string as guid when '--guid' flag is provided and stack doesn't exist", func() {
		stack1 := models.Stack{
			Name:        "Stack-1",
			Description: "Stack 1 Description",
			Guid:        "Stack-1-GUID",
		}

		repo.FindByNameReturns(stack1, nil)

		testcmd.RunCliCommand("stack", []string{"Stack-1", "--guid"}, requirementsFactory, updateCommandDependency, false)

		Expect(len(ui.Outputs)).To(Equal(1))
		Expect(ui.Outputs[0]).To(Equal("Stack-1-GUID"))
	})

	It("lists the stack requested", func() {
		repo.FindByNameReturns(models.Stack{}, errors.New("Stack Stack-1 not found"))

		testcmd.RunCliCommand("stack", []string{"Stack-1", "--guid"}, requirementsFactory, updateCommandDependency, false)

		Expect(len(ui.Outputs)).To(Equal(1))
		Expect(ui.Outputs[0]).To(Equal(""))
	})

	It("informs user if stack is not found", func() {
		repo.FindByNameReturns(models.Stack{}, errors.New("Stack Stack-1 not found"))

		testcmd.RunCliCommand("stack", []string{"Stack-1"}, requirementsFactory, updateCommandDependency, false)

		Expect(ui.Outputs).To(BeInDisplayOrder(
			[]string{"FAILED"},
			[]string{"Stack Stack-1 not found"},
		))
	})
})
