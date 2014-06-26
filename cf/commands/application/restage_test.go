package application_test

import (
	testapi "github.com/cloudfoundry/cli/cf/api/fakes"
	. "github.com/cloudfoundry/cli/cf/commands/application"
	"github.com/cloudfoundry/cli/cf/configuration"
	"github.com/cloudfoundry/cli/cf/errors"
	"github.com/cloudfoundry/cli/cf/models"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("restage command", func() {
	var (
		ui                  *testterm.FakeUI
		app                 models.Application
		appRepo             *testapi.FakeApplicationRepository
		configRepo          configuration.ReadWriter
		requirementsFactory *testreq.FakeReqFactory
		stagingWatcher      *fakeStagingWatcher
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}

		app = models.Application{}
		app.Name = "my-app"
		appRepo = &testapi.FakeApplicationRepository{}
		appRepo.ReadReturns.App = app

		configRepo = testconfig.NewRepositoryWithDefaults()
		requirementsFactory = &testreq.FakeReqFactory{LoginSuccess: true}

		stagingWatcher = &fakeStagingWatcher{}
	})

	runCommand := func(args ...string) {
		cmd := NewRestage(ui, configRepo, appRepo, stagingWatcher)
		testcmd.RunCommand(cmd, args, requirementsFactory)
	}

	Describe("Requirements", func() {
		It("fails when the user is not logged in", func() {
			requirementsFactory.LoginSuccess = false
			runCommand("my-app")
			Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
		})

		It("fails with usage when no arguments are given", func() {
			runCommand()
			Expect(ui.FailedWithUsage).To(BeTrue())
			Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
		})
	})

	It("fails with usage when the app cannot be found", func() {
		appRepo.ReadReturns.Error = errors.NewModelNotFoundError("app", "hocus-pocus")
		runCommand("hocus-pocus")

		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"FAILED"},
			[]string{"not found"},
		))
	})

	Context("when the app is found", func() {
		BeforeEach(func() {
			app = models.Application{}
			app.Name = "my-app"
			app.Guid = "the-app-guid"

			appRepo.ReadReturns.App = app
		})

		It("sends a restage request", func() {
			runCommand("my-app")
			Expect(appRepo.CreateRestageRequestArgs.AppGuid).To(Equal("the-app-guid"))
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Restaging app", "my-app", "my-org", "my-space", "my-user"},
			))
		})

		It("watches the staging output", func() {
			runCommand("my-app")
			Expect(stagingWatcher.watched).To(Equal(app))
		})
	})
})

type fakeStagingWatcher struct {
	watched models.Application
}

func (f *fakeStagingWatcher) ApplicationWatchStaging(app models.Application, start func(models.Application) (models.Application, error)) (updatedApp models.Application, err error) {
	f.watched = app
	return start(app)
}
