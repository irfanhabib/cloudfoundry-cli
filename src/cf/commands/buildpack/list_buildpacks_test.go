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

package buildpack_test

import (
	"cf/commands/buildpack"
	"cf/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	testapi "testhelpers/api"
	testassert "testhelpers/assert"
	testcmd "testhelpers/commands"
	testreq "testhelpers/requirements"
	testterm "testhelpers/terminal"
)

func callListBuildpacks(reqFactory *testreq.FakeReqFactory, buildpackRepo *testapi.FakeBuildpackRepository) (ui *testterm.FakeUI) {
	ui = &testterm.FakeUI{}
	ctxt := testcmd.NewContext("buildpacks", []string{})
	cmd := buildpack.NewListBuildpacks(ui, buildpackRepo)
	testcmd.RunCommand(cmd, ctxt, reqFactory)
	return
}

var _ = Describe("ListBuildpacks", func() {
	It("has the right requirements", func() {
		buildpackRepo := &testapi.FakeBuildpackRepository{}

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}
		callListBuildpacks(reqFactory, buildpackRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeTrue())

		reqFactory = &testreq.FakeReqFactory{LoginSuccess: false}
		callListBuildpacks(reqFactory, buildpackRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
	})

	It("lists buildpacks", func() {
		p1 := 5
		p2 := 10
		p3 := 15
		t := true
		f := false

		buildpackRepo := &testapi.FakeBuildpackRepository{
			Buildpacks: []models.Buildpack{
				models.Buildpack{Name: "Buildpack-1", Position: &p1, Enabled: &t, Locked: &f},
				models.Buildpack{Name: "Buildpack-2", Position: &p2, Enabled: &f, Locked: &t},
				models.Buildpack{Name: "Buildpack-3", Position: &p3, Enabled: &t, Locked: &f},
			},
		}

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		ui := callListBuildpacks(reqFactory, buildpackRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting buildpacks"},
			{"buildpack", "position", "enabled"},
			{"Buildpack-1", "5", "true", "false"},
			{"Buildpack-2", "10", "false", "true"},
			{"Buildpack-3", "15", "true", "false"},
		})
	})

	It("TestListingBuildpacksWhenNoneExist", func() {
		buildpackRepo := &testapi.FakeBuildpackRepository{
			Buildpacks: []models.Buildpack{},
		}

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		ui := callListBuildpacks(reqFactory, buildpackRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting buildpacks"},
			{"No buildpacks found"},
		})
	})
})
