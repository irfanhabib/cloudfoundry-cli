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

package serviceauthtoken_test

import (
	. "cf/commands/serviceauthtoken"
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

func callUpdateServiceAuthToken(args []string, reqFactory *testreq.FakeReqFactory, authTokenRepo *testapi.FakeAuthTokenRepo) (ui *testterm.FakeUI) {
	ui = new(testterm.FakeUI)

	config := testconfig.NewRepositoryWithDefaults()

	cmd := NewUpdateServiceAuthToken(ui, config, authTokenRepo)
	ctxt := testcmd.NewContext("update-service-auth-token", args)

	testcmd.RunCommand(cmd, ctxt, reqFactory)
	return
}

var _ = Describe("Testing with ginkgo", func() {
	It("TestUpdateServiceAuthTokenFailsWithUsage", func() {
		authTokenRepo := &testapi.FakeAuthTokenRepo{}
		reqFactory := &testreq.FakeReqFactory{}

		ui := callUpdateServiceAuthToken([]string{}, reqFactory, authTokenRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())

		ui = callUpdateServiceAuthToken([]string{"MY-TOKEN-LABEL"}, reqFactory, authTokenRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())

		ui = callUpdateServiceAuthToken([]string{"MY-TOKEN-LABEL", "my-token-abc123"}, reqFactory, authTokenRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())

		ui = callUpdateServiceAuthToken([]string{"MY-TOKEN-LABEL", "my-provider", "my-token-abc123"}, reqFactory, authTokenRepo)
		Expect(ui.FailedWithUsage).To(BeFalse())
	})
	It("TestUpdateServiceAuthTokenRequirements", func() {

		authTokenRepo := &testapi.FakeAuthTokenRepo{}
		reqFactory := &testreq.FakeReqFactory{}
		args := []string{"MY-TOKEN-LABLE", "my-provider", "my-token-abc123"}

		reqFactory.LoginSuccess = true
		callUpdateServiceAuthToken(args, reqFactory, authTokenRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeTrue())

		reqFactory.LoginSuccess = false
		callUpdateServiceAuthToken(args, reqFactory, authTokenRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
	})
	It("TestUpdateServiceAuthToken", func() {

		foundAuthToken := models.ServiceAuthTokenFields{}
		foundAuthToken.Guid = "found-auth-token-guid"
		foundAuthToken.Label = "found label"
		foundAuthToken.Provider = "found provider"

		authTokenRepo := &testapi.FakeAuthTokenRepo{FindByLabelAndProviderServiceAuthTokenFields: foundAuthToken}
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}
		args := []string{"a label", "a provider", "a value"}

		ui := callUpdateServiceAuthToken(args, reqFactory, authTokenRepo)
		expectedAuthToken := models.ServiceAuthTokenFields{}
		expectedAuthToken.Guid = "found-auth-token-guid"
		expectedAuthToken.Label = "found label"
		expectedAuthToken.Provider = "found provider"
		expectedAuthToken.Token = "a value"

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Updating service auth token as", "my-user"},
			{"OK"},
		})

		Expect(authTokenRepo.FindByLabelAndProviderLabel).To(Equal("a label"))
		Expect(authTokenRepo.FindByLabelAndProviderProvider).To(Equal("a provider"))
		Expect(authTokenRepo.UpdatedServiceAuthTokenFields).To(Equal(expectedAuthToken))
		Expect(authTokenRepo.UpdatedServiceAuthTokenFields).To(Equal(expectedAuthToken))
	})
})
