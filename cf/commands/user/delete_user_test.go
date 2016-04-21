package user_test

import (
	"github.com/cloudfoundry/cli/cf/api/apifakes"
	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/errors"
	"github.com/cloudfoundry/cli/cf/models"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/cli/testhelpers/matchers"
)

var _ = Describe("delete-user command", func() {
	var (
		ui                  *testterm.FakeUI
		configRepo          coreconfig.Repository
		userRepo            *apifakes.FakeUserRepository
		requirementsFactory *testreq.FakeReqFactory
		deps                commandregistry.Dependency
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.UI = ui
		deps.Config = configRepo
		deps.RepoLocator = deps.RepoLocator.SetUserRepository(userRepo)
		commandregistry.Commands.SetCommand(commandregistry.Commands.FindCommand("delete-user").SetDependency(deps, pluginCall))
	}

	BeforeEach(func() {
		ui = &testterm.FakeUI{Inputs: []string{"y"}}
		userRepo = new(apifakes.FakeUserRepository)
		requirementsFactory = &testreq.FakeReqFactory{LoginSuccess: true}
		configRepo = testconfig.NewRepositoryWithDefaults()

		token, err := testconfig.EncodeAccessToken(coreconfig.TokenInfo{
			UserGUID: "admin-user-guid",
			Username: "admin-user",
		})
		Expect(err).ToNot(HaveOccurred())
		configRepo.SetAccessToken(token)
	})

	runCommand := func(args ...string) bool {
		return testcmd.RunCLICommand("delete-user", args, requirementsFactory, updateCommandDependency, false)
	}

	Describe("requirements", func() {
		It("fails when not logged in", func() {
			requirementsFactory.LoginSuccess = false

			Expect(runCommand("my-user")).To(BeFalse())
		})

		It("fails with usage when no arguments are given", func() {
			runCommand()
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Incorrect Usage", "Requires an argument"},
			))
		})
	})

	Context("when the given user exists", func() {
		BeforeEach(func() {
			userRepo.FindByUsernameReturns(models.UserFields{
				Username: "user-name",
				GUID:     "user-guid",
			}, nil)
		})

		It("deletes a user with the given name", func() {
			runCommand("user-name")

			Expect(ui.Prompts).To(ContainSubstrings([]string{"Really delete the user user-name"}))

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Deleting user", "user-name", "admin-user"},
				[]string{"OK"},
			))

			Expect(userRepo.FindByUsernameArgsForCall(0)).To(Equal("user-name"))
			Expect(userRepo.DeleteArgsForCall(0)).To(Equal("user-guid"))
		})

		It("does not delete the user when no confirmation is given", func() {
			ui.Inputs = []string{"nope"}
			runCommand("user")

			Expect(ui.Prompts).To(ContainSubstrings([]string{"Really delete"}))
			Expect(userRepo.FindByUsernameCallCount()).To(BeZero())
			Expect(userRepo.DeleteCallCount()).To(BeZero())
		})

		It("deletes without confirmation when the -f flag is given", func() {
			ui.Inputs = []string{}
			runCommand("-f", "user-name")

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Deleting user", "user-name"},
				[]string{"OK"},
			))

			Expect(userRepo.FindByUsernameArgsForCall(0)).To(Equal("user-name"))
			Expect(userRepo.DeleteArgsForCall(0)).To(Equal("user-guid"))
		})
	})

	Context("when the given user does not exist", func() {
		BeforeEach(func() {
			userRepo.FindByUsernameReturns(models.UserFields{}, errors.NewModelNotFoundError("User", ""))
		})

		It("prints a warning", func() {
			runCommand("-f", "user-name")

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Deleting user", "user-name"},
				[]string{"OK"},
			))

			Expect(ui.WarnOutputs).To(ContainSubstrings([]string{"user-name", "does not exist"}))

			Expect(userRepo.FindByUsernameArgsForCall(0)).To(Equal("user-name"))
			Expect(userRepo.DeleteCallCount()).To(BeZero())
		})
	})
})
