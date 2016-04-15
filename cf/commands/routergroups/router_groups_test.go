package routergroups_test

import (
	"errors"

	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/api/apifakes"
	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/requirements/requirementsfakes"
	"github.com/cloudfoundry/cli/flags"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	"github.com/cloudfoundry/cli/cf/commands/routergroups"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RouterGroups", func() {

	var (
		ui             *testterm.FakeUI
		routingApiRepo *apifakes.FakeRoutingApiRepository
		deps           commandregistry.Dependency
		cmd            *routergroups.RouterGroups
		flagContext    flags.FlagContext
		repoLocator    api.RepositoryLocator
		config         coreconfig.Repository

		requirementsFactory           *requirementsfakes.FakeFactory
		minAPIVersionRequirement      *requirementsfakes.FakeRequirement
		loginRequirement              *requirementsfakes.FakeRequirement
		routingApiEndpoingRequirement *requirementsfakes.FakeRequirement
	)

	BeforeEach(func() {
		ui = new(testterm.FakeUI)
		routingApiRepo = new(apifakes.FakeRoutingApiRepository)
		config = testconfig.NewRepositoryWithDefaults()
		repoLocator = api.RepositoryLocator{}.SetRoutingApiRepository(routingApiRepo)
		deps = commandregistry.Dependency{
			Ui:          ui,
			Config:      config,
			RepoLocator: repoLocator,
		}

		minAPIVersionRequirement = new(requirementsfakes.FakeRequirement)
		loginRequirement = new(requirementsfakes.FakeRequirement)
		routingApiEndpoingRequirement = new(requirementsfakes.FakeRequirement)

		requirementsFactory = new(requirementsfakes.FakeFactory)
		requirementsFactory.NewMinAPIVersionRequirementReturns(minAPIVersionRequirement)
		requirementsFactory.NewLoginRequirementReturns(loginRequirement)
		requirementsFactory.NewRoutingAPIRequirementReturns(routingApiEndpoingRequirement)

		cmd = new(routergroups.RouterGroups)
		cmd = cmd.SetDependency(deps, false).(*routergroups.RouterGroups)
		flagContext = flags.NewFlagContext(cmd.MetaData().Flags)
	})

	runCommand := func(args ...string) error {
		err := flagContext.Parse(args...)
		if err != nil {
			return err
		}

		cmd.Execute(flagContext)
		return nil
	}

	Describe("login requirements", func() {
		It("fails if the user is not logged in", func() {
			cmd.Requirements(requirementsFactory, flagContext)

			Expect(requirementsFactory.NewLoginRequirementCallCount()).To(Equal(1))
		})

		It("fails when the routing API endpoint is not set", func() {
			cmd.Requirements(requirementsFactory, flagContext)

			Expect(requirementsFactory.NewRoutingAPIRequirementCallCount()).To(Equal(1))
		})

		It("should fail with usage", func() {
			flagContext.Parse("blahblah")
			cmd.Requirements(requirementsFactory, flagContext)

			Expect(requirementsFactory.NewUsageRequirementCallCount()).To(Equal(1))
		})
	})

	Context("when there are router groups", func() {
		BeforeEach(func() {
			routerGroups := models.RouterGroups{
				models.RouterGroup{
					Guid: "guid-0001",
					Name: "default-router-group",
					Type: "tcp",
				},
			}
			routingApiRepo.ListRouterGroupsStub = func(cb func(models.RouterGroup) bool) (apiErr error) {
				for _, r := range routerGroups {
					if !cb(r) {
						break
					}
				}
				return nil
			}
		})

		It("lists router groups", func() {
			runCommand()

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Getting router groups", "my-user"},
				[]string{"name", "type"},
				[]string{"default-router-group", "tcp"},
			))
		})
	})

	Context("when there are no router groups", func() {
		It("tells the user when no router groups were found", func() {
			runCommand()

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Getting router groups"},
				[]string{"No router groups found"},
			))
		})
	})

	Context("when there is an error listing router groups", func() {
		BeforeEach(func() {
			routingApiRepo.ListRouterGroupsReturns(errors.New("BOOM"))
		})

		It("returns an error to the user", func() {
			Expect(func() {
				runCommand()
			}).To(Panic())

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Getting router groups"},
				[]string{"Failed fetching router groups"},
			))
		})
	})

})
