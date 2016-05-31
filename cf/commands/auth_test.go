package commands_test

import (
	"errors"

	"github.com/cloudfoundry/cli/cf"
	"github.com/cloudfoundry/cli/cf/api/authentication/authenticationfakes"
	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/trace/tracefakes"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	"os"
)

var _ = Describe("auth command", func() {
	var (
		ui                  *testterm.FakeUI
		config              coreconfig.Repository
		authRepo            *authenticationfakes.FakeAuthenticationRepository
		requirementsFactory *testreq.FakeReqFactory
		deps                commandregistry.Dependency
		fakeLogger          *tracefakes.FakePrinter
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.UI = ui
		deps.Config = config
		deps.RepoLocator = deps.RepoLocator.SetAuthenticationRepository(authRepo)
		commandregistry.Commands.SetCommand(commandregistry.Commands.FindCommand("auth").SetDependency(deps, pluginCall))
	}

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		config = testconfig.NewRepositoryWithDefaults()
		requirementsFactory = &testreq.FakeReqFactory{}
		authRepo = new(authenticationfakes.FakeAuthenticationRepository)
		authRepo.AuthenticateStub = func(credentials map[string]string) error {
			config.SetAccessToken("my-access-token")
			config.SetRefreshToken("my-refresh-token")
			return nil
		}

		fakeLogger = new(tracefakes.FakePrinter)
		deps = commandregistry.NewDependency(os.Stdout, fakeLogger)
	})

	Describe("requirements", func() {
		It("fails with usage when given too few arguments", func() {
			testcmd.RunCLICommand("auth", []string{}, requirementsFactory, updateCommandDependency, false, ui)

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Incorrect Usage", "Requires", "arguments"},
			))
		})

		It("fails if the user has not set an api endpoint", func() {
			Expect(testcmd.RunCLICommand("auth", []string{"username", "password"}, requirementsFactory, updateCommandDependency, false, ui)).To(BeFalse())
		})
	})

	Context("when an api endpoint is targeted", func() {
		BeforeEach(func() {
			requirementsFactory.APIEndpointSuccess = true
			config.SetAPIEndpoint("foo.example.org/authenticate")
		})

		It("authenticates successfully", func() {
			requirementsFactory.APIEndpointSuccess = true
			testcmd.RunCLICommand("auth", []string{"foo@example.com", "password"}, requirementsFactory, updateCommandDependency, false, ui)

			Expect(ui.FailedWithUsage).To(BeFalse())
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"foo.example.org/authenticate"},
				[]string{"OK"},
			))

			Expect(authRepo.AuthenticateArgsForCall(0)).To(Equal(map[string]string{
				"username": "foo@example.com",
				"password": "password",
			}))
		})

		It("prompts users to upgrade if CLI version < min cli version requirement", func() {
			config.SetMinCLIVersion("5.0.0")
			config.SetMinRecommendedCLIVersion("5.5.0")
			cf.Version = "4.5.0"

			testcmd.RunCLICommand("auth", []string{"foo@example.com", "password"}, requirementsFactory, updateCommandDependency, false, ui)

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"To upgrade your CLI"},
				[]string{"5.0.0"},
			))
		})

		It("gets the UAA endpoint and saves it to the config file", func() {
			requirementsFactory.APIEndpointSuccess = true
			testcmd.RunCLICommand("auth", []string{"foo@example.com", "password"}, requirementsFactory, updateCommandDependency, false, ui)
			Expect(authRepo.GetLoginPromptsAndSaveUAAServerURLCallCount()).To(Equal(1))
		})

		Describe("when authentication fails", func() {
			BeforeEach(func() {
				authRepo.AuthenticateReturns(errors.New("Error authenticating."))
				testcmd.RunCLICommand("auth", []string{"username", "password"}, requirementsFactory, updateCommandDependency, false, ui)
			})

			It("does not prompt the user when provided username and password", func() {
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{config.APIEndpoint()},
					[]string{"Authenticating..."},
					[]string{"FAILED"},
					[]string{"Error authenticating"},
				))
			})

			It("clears the user's session", func() {
				Expect(config.AccessToken()).To(BeEmpty())
				Expect(config.RefreshToken()).To(BeEmpty())
				Expect(config.SpaceFields()).To(Equal(models.SpaceFields{}))
				Expect(config.OrganizationFields()).To(Equal(models.OrganizationFields{}))
			})
		})
	})
})
