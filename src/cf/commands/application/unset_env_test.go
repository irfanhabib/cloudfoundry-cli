/*
                       WARNING WARNING WARNING

                Attention all potential contributors

   This testfile is not in the best state. We've been slowly transitioning
   from the built in "testing" package to using Ginkgo. As you can see, we've
   changed the format, but a lot of the setup, test body, descriptions, etc
   are either hardcoded, completely lacking, or misleading.

   For example:

   Describe("Testing with ginkgo"...)      // This is not a great description
   It("TestDoesSoemthing"...)              // This is a horrible description

   Describe("create-user command"...       // Describe the actual object under test
   It("creates a user when provided ..."   // this is more descriptive

   For good examples of writing Ginkgo tests for the cli, refer to

   src/cf/commands/application/delete_app_test.go
   src/cf/terminal/ui_test.go
   src/github.com/cloudfoundry/loggregator_consumer/consumer_test.go
*/

package application_test

import (
	"cf/api"
	. "cf/commands/application"
	"cf/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	testapi "testhelpers/api"
	testassert "testhelpers/assert"
	testcmd "testhelpers/commands"
	testconfig "testhelpers/configuration"
	testreq "testhelpers/requirements"
	testterm "testhelpers/terminal"
)

var _ = Describe("Testing with ginkgo", func() {
	It("TestUnsetEnvRequirements", func() {
		app := models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"
		appRepo := &testapi.FakeApplicationRepository{}
		args := []string{"my-app", "DATABASE_URL"}

		reqFactory := &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: true}
		callUnsetEnv(args, reqFactory, appRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeTrue())

		reqFactory = &testreq.FakeReqFactory{Application: app, LoginSuccess: false, TargetedSpaceSuccess: true}
		callUnsetEnv(args, reqFactory, appRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())

		reqFactory = &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: false}
		callUnsetEnv(args, reqFactory, appRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
	})
	It("TestUnsetEnvWhenApplicationExists", func() {

		app := models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"
		app.EnvironmentVars = map[string]string{"foo": "bar", "DATABASE_URL": "mysql://example.com/my-db"}
		reqFactory := &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: true}
		appRepo := &testapi.FakeApplicationRepository{}

		args := []string{"my-app", "DATABASE_URL"}
		ui := callUnsetEnv(args, reqFactory, appRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Removing env variable", "DATABASE_URL", "my-app", "my-org", "my-space", "my-user"},
			{"OK"},
		})

		Expect(reqFactory.ApplicationName).To(Equal("my-app"))
		Expect(appRepo.UpdateAppGuid).To(Equal("my-app-guid"))
		Expect(*appRepo.UpdateParams.EnvironmentVars).To(Equal(map[string]string{
			"foo": "bar",
		}))
	})

	It("TestUnsetEnvWhenUnsettingTheEnvFails", func() {
		app := models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"
		app.EnvironmentVars = map[string]string{"DATABASE_URL": "mysql://example.com/my-db"}
		reqFactory := &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: true}
		appRepo := &testapi.FakeApplicationRepository{
			UpdateErr: true,
		}
		appRepo.ReadReturns.App = app

		args := []string{"does-not-exist", "DATABASE_URL"}
		ui := callUnsetEnv(args, reqFactory, appRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Removing env variable"},
			{"FAILED"},
			{"Error updating app."},
		})
	})
	It("TestUnsetEnvWhenEnvVarDoesNotExist", func() {

		app := models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"
		reqFactory := &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: true}
		appRepo := &testapi.FakeApplicationRepository{}

		args := []string{"my-app", "DATABASE_URL"}
		ui := callUnsetEnv(args, reqFactory, appRepo)

		Expect(len(ui.Outputs)).To(Equal(3))
		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Removing env variable"},
			{"OK"},
			{"DATABASE_URL", "was not set."},
		})
	})

	It("TestUnsetEnvFailsWithUsage", func() {
		app := models.Application{}
		app.Name = "my-app"
		app.Guid = "my-app-guid"
		reqFactory := &testreq.FakeReqFactory{Application: app, LoginSuccess: true, TargetedSpaceSuccess: true}
		appRepo := &testapi.FakeApplicationRepository{}
		appRepo.ReadReturns.App = app

		args := []string{"my-app", "DATABASE_URL"}
		ui := callUnsetEnv(args, reqFactory, appRepo)
		Expect(ui.FailedWithUsage).To(BeFalse())

		args = []string{"my-app"}
		ui = callUnsetEnv(args, reqFactory, appRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())

		args = []string{}
		ui = callUnsetEnv(args, reqFactory, appRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())
	})
})

func callUnsetEnv(args []string, reqFactory *testreq.FakeReqFactory, appRepo api.ApplicationRepository) (ui *testterm.FakeUI) {
	ui = new(testterm.FakeUI)
	ctxt := testcmd.NewContext("unset-env", args)
	configRepo := testconfig.NewRepositoryWithDefaults()
	cmd := NewUnsetEnv(ui, configRepo, appRepo)
	testcmd.RunCommand(cmd, ctxt, reqFactory)
	return
}
