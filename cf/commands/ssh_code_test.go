package commands_test

import (
	"errors"

	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/commands"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig/coreconfigfakes"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/requirements/requirementsfakes"
	"github.com/cloudfoundry/cli/flags"

	"github.com/cloudfoundry/cli/cf/api/authentication/authenticationfakes"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("OneTimeSSHCode", func() {
	var (
		ui           *testterm.FakeUI
		configRepo   coreconfig.Repository
		authRepo     *authenticationfakes.FakeAuthenticationRepository
		endpointRepo *coreconfigfakes.FakeEndpointRepository

		cmd         commandregistry.Command
		deps        commandregistry.Dependency
		factory     *requirementsfakes.FakeFactory
		flagContext flags.FlagContext

		endpointRequirement requirements.Requirement
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}

		configRepo = testconfig.NewRepositoryWithDefaults()
		configRepo.SetApiEndpoint("fake-api-endpoint")
		endpointRepo = new(coreconfigfakes.FakeEndpointRepository)
		repoLocator := deps.RepoLocator.SetEndpointRepository(endpointRepo)
		authRepo = new(authenticationfakes.FakeAuthenticationRepository)
		repoLocator = repoLocator.SetAuthenticationRepository(authRepo)

		deps = commandregistry.Dependency{
			Ui:          ui,
			Config:      configRepo,
			RepoLocator: repoLocator,
		}

		cmd = &commands.OneTimeSSHCode{}
		cmd.SetDependency(deps, false)

		flagContext = flags.NewFlagContext(cmd.MetaData().Flags)

		factory = new(requirementsfakes.FakeFactory)

		endpointRequirement = &passingRequirement{Name: "endpoint-requirement"}
		factory.NewApiEndpointRequirementReturns(endpointRequirement)
	})

	Describe("Requirements", func() {
		It("returns an EndpointRequirement", func() {
			actualRequirements := cmd.Requirements(factory, flagContext)
			Expect(factory.NewApiEndpointRequirementCallCount()).To(Equal(1))
			Expect(actualRequirements).To(ContainElement(endpointRequirement))
		})

		Context("when not provided exactly zero args", func() {
			BeforeEach(func() {
				flagContext.Parse("domain-name")
			})

			It("fails with usage", func() {
				var firstErr error

				reqs := cmd.Requirements(factory, flagContext)

				for _, req := range reqs {
					err := req.Execute()
					if err != nil {
						firstErr = err
						break
					}
				}

				Expect(firstErr.Error()).To(ContainSubstring("Incorrect Usage. No argument required"))
			})
		})
	})

	Describe("Execute", func() {
		BeforeEach(func() {
			cmd.Requirements(factory, flagContext)

			endpointRepo.GetCCInfoReturns(
				&coreconfig.CCInfo{
					LoggregatorEndpoint: "loggregator/endpoint",
				},
				"some-endpoint",
				nil,
			)
		})

		It("tries to update the endpoint", func() {
			cmd.Execute(flagContext)
			Expect(endpointRepo.GetCCInfoCallCount()).To(Equal(1))
			Expect(endpointRepo.GetCCInfoArgsForCall(0)).To(Equal("fake-api-endpoint"))
		})

		Context("when updating the endpoint succeeds", func() {
			ccInfo := &coreconfig.CCInfo{
				ApiVersion:               "some-version",
				AuthorizationEndpoint:    "auth/endpoint",
				LoggregatorEndpoint:      "loggregator/endpoint",
				MinCliVersion:            "min-cli-version",
				MinRecommendedCliVersion: "min-rec-cli-version",
				SSHOAuthClient:           "some-client",
				RoutingApiEndpoint:       "routing/endpoint",
			}
			BeforeEach(func() {
				endpointRepo.GetCCInfoReturns(
					ccInfo,
					"updated-endpoint",
					nil,
				)
			})

			It("tries to refresh the auth token", func() {
				cmd.Execute(flagContext)
				Expect(authRepo.RefreshAuthTokenCallCount()).To(Equal(1))
			})

			Context("when refreshing the token fails with an error", func() {
				BeforeEach(func() {
					authRepo.RefreshAuthTokenReturns("", errors.New("auth-error"))
				})

				It("fails with error", func() {
					Expect(func() { cmd.Execute(flagContext) }).To(Panic())
					Expect(ui.Outputs).To(ContainSubstrings(
						[]string{"FAILED"},
						[]string{"Error refreshing oauth token"},
					))
				})
			})

			Context("when refreshing the token succeeds", func() {
				BeforeEach(func() {
					authRepo.RefreshAuthTokenReturns("auth-token", nil)
				})

				It("tries to get the ssh-code", func() {
					cmd.Execute(flagContext)
					Expect(authRepo.AuthorizeCallCount()).To(Equal(1))
					Expect(authRepo.AuthorizeArgsForCall(0)).To(Equal("auth-token"))
				})

				Context("when getting the ssh-code succeeds", func() {
					BeforeEach(func() {
						authRepo.AuthorizeReturns("some-code", nil)
					})

					It("displays the token", func() {
						cmd.Execute(flagContext)
						Expect(ui.Outputs).To(ContainSubstrings(
							[]string{"some-code"},
						))
					})
				})

				Context("when getting the ssh-code fails", func() {
					BeforeEach(func() {
						authRepo.AuthorizeReturns("", errors.New("auth-err"))
					})

					It("fails with error", func() {
						Expect(func() { cmd.Execute(flagContext) }).To(Panic())
						Expect(ui.Outputs).To(ContainSubstrings(
							[]string{"FAILED"},
							[]string{"Error getting SSH code: auth-err"},
						))
					})
				})
			})
		})
	})
})
