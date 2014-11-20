package application_test

import (
	testapi "github.com/cloudfoundry/cli/cf/api/fakes"
	. "github.com/cloudfoundry/cli/cf/commands/application"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/models"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/cli/testhelpers/matchers"
)

var _ = Describe("list-apps command", func() {
	var (
		ui                  *testterm.FakeUI
		configRepo          core_config.ReadWriter
		appSummaryRepo      *testapi.FakeAppSummaryRepo
		requirementsFactory *testreq.FakeReqFactory
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		appSummaryRepo = &testapi.FakeAppSummaryRepo{}
		configRepo = testconfig.NewRepositoryWithDefaults()
		requirementsFactory = &testreq.FakeReqFactory{
			LoginSuccess:         true,
			TargetedSpaceSuccess: true,
		}
	})

	runCommand := func(args ...string) bool {
		cmd := NewListApps(ui, configRepo, appSummaryRepo)
		return testcmd.RunCommand(cmd, args, requirementsFactory)
	}

	Describe("requirements", func() {
		It("requires the user to be logged in", func() {
			requirementsFactory.LoginSuccess = false

			Expect(runCommand()).To(BeFalse())
		})

		It("requires the user to have a space targeted", func() {
			requirementsFactory.TargetedSpaceSuccess = false

			Expect(runCommand()).To(BeFalse())
		})
		It("should fail with usage when provided any arguments", func() {
			requirementsFactory.LoginSuccess = true
			requirementsFactory.TargetedSpaceSuccess = true
			Expect(runCommand("blahblah")).To(BeFalse())
			Expect(ui.FailedWithUsage).To(BeTrue())
		})
	})

	Context("when the user is logged in and a space is targeted", func() {
		It("lists apps in a table", func() {
			app1Routes := []models.RouteSummary{
				models.RouteSummary{
					Host: "app1",
					Domain: models.DomainFields{
						Name: "cfapps.io",
					},
				},
				models.RouteSummary{
					Host: "app1",
					Domain: models.DomainFields{
						Name: "example.com",
					},
				}}

			app2Routes := []models.RouteSummary{
				models.RouteSummary{
					Host:   "app2",
					Domain: models.DomainFields{Name: "cfapps.io"},
				}}

			app := models.Application{}
			app.Name = "Application-1"
			app.State = "started"
			app.RunningInstances = 1
			app.InstanceCount = 1
			app.Memory = 512
			app.DiskQuota = 1024
			app.Routes = app1Routes

			app2 := models.Application{}
			app2.Name = "Application-2"
			app2.State = "started"
			app2.RunningInstances = 1
			app2.InstanceCount = 2
			app2.Memory = 256
			app2.DiskQuota = 1024
			app2.Routes = app2Routes

			appSummaryRepo.GetSummariesInCurrentSpaceApps = []models.Application{app, app2}

			runCommand()

			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Getting apps in", "my-org", "my-space", "my-user"},
				[]string{"OK"},
				[]string{"Application-1", "started", "1/1", "512M", "1G", "app1.cfapps.io", "app1.example.com"},
				[]string{"Application-2", "started", "1/2", "256M", "1G", "app2.cfapps.io"},
			))
		})

		Context("when an app's running instances is unknown", func() {
			It("dipslays a '?' for running instances", func() {
				appRoutes := []models.RouteSummary{
					models.RouteSummary{
						Host:   "app1",
						Domain: models.DomainFields{Name: "cfapps.io"},
					}}
				app := models.Application{}
				app.Name = "Application-1"
				app.State = "started"
				app.RunningInstances = -1
				app.InstanceCount = 2
				app.Memory = 512
				app.DiskQuota = 1024
				app.Routes = appRoutes

				appSummaryRepo.GetSummariesInCurrentSpaceApps = []models.Application{app}

				runCommand()

				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Getting apps in", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"Application-1", "started", "?/2", "512M", "1G", "app1.cfapps.io"},
				))
			})
		})

		Context("when there are no apps", func() {
			It("tells the user that there are no apps", func() {
				runCommand()
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Getting apps in", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"No apps found"},
				))
			})
		})
	})
})
