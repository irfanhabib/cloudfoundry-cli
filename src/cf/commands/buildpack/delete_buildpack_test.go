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
	. "cf/commands/buildpack"
	"cf/errors"
	"cf/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	testapi "testhelpers/api"
	testassert "testhelpers/assert"
	testcmd "testhelpers/commands"
	testreq "testhelpers/requirements"
	testterm "testhelpers/terminal"
)

var _ = Describe("delete-buildpack command", func() {
	It("TestDeleteBuildpackGetRequirements", func() {

		ui := &testterm.FakeUI{Inputs: []string{"y"}}
		buildpackRepo := &testapi.FakeBuildpackRepository{}
		cmd := NewDeleteBuildpack(ui, buildpackRepo)

		ctxt := testcmd.NewContext("delete-buildpack", []string{"my-buildpack"})

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}
		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(testcmd.CommandDidPassRequirements).To(BeTrue())

		reqFactory = &testreq.FakeReqFactory{LoginSuccess: false}
		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
	})
	It("TestDeleteBuildpackSuccess", func() {

		ui := &testterm.FakeUI{Inputs: []string{"y"}}
		buildpack := models.Buildpack{}
		buildpack.Name = "my-buildpack"
		buildpack.Guid = "my-buildpack-guid"
		buildpackRepo := &testapi.FakeBuildpackRepository{
			FindByNameBuildpack: buildpack,
		}
		cmd := NewDeleteBuildpack(ui, buildpackRepo)

		ctxt := testcmd.NewContext("delete-buildpack", []string{"my-buildpack"})
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(buildpackRepo.DeleteBuildpackGuid).To(Equal("my-buildpack-guid"))

		testassert.SliceContains(ui.Prompts, testassert.Lines{
			{"delete", "my-buildpack"},
		})
		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Deleting buildpack", "my-buildpack"},
			{"OK"},
		})
	})
	It("TestDeleteBuildpackNoConfirmation", func() {

		ui := &testterm.FakeUI{Inputs: []string{"no"}}
		buildpack := models.Buildpack{}
		buildpack.Name = "my-buildpack"
		buildpack.Guid = "my-buildpack-guid"
		buildpackRepo := &testapi.FakeBuildpackRepository{
			FindByNameBuildpack: buildpack,
		}
		cmd := NewDeleteBuildpack(ui, buildpackRepo)

		ctxt := testcmd.NewContext("delete-buildpack", []string{"my-buildpack"})
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(buildpackRepo.DeleteBuildpackGuid).To(Equal(""))

		testassert.SliceContains(ui.Prompts, testassert.Lines{
			{"delete", "my-buildpack"},
		})
	})
	It("TestDeleteBuildpackThatDoesNotExist", func() {

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}
		buildpack := models.Buildpack{}
		buildpack.Name = "my-buildpack"
		buildpack.Guid = "my-buildpack-guid"
		buildpackRepo := &testapi.FakeBuildpackRepository{
			FindByNameNotFound:  true,
			FindByNameBuildpack: buildpack,
		}

		ui := &testterm.FakeUI{}
		ctxt := testcmd.NewContext("delete-buildpack", []string{"-f", "my-buildpack"})

		cmd := NewDeleteBuildpack(ui, buildpackRepo)
		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(buildpackRepo.FindByNameName).To(Equal("my-buildpack"))
		Expect(buildpackRepo.FindByNameNotFound).To(BeTrue())

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Deleting", "my-buildpack"},
			{"OK"},
			{"my-buildpack", "does not exist"},
		})
	})
	It("TestDeleteBuildpackDeleteError", func() {

		ui := &testterm.FakeUI{Inputs: []string{"y"}}
		buildpack := models.Buildpack{}
		buildpack.Name = "my-buildpack"
		buildpack.Guid = "my-buildpack-guid"
		buildpackRepo := &testapi.FakeBuildpackRepository{
			FindByNameBuildpack: buildpack,
			DeleteApiResponse:   errors.New("failed badly"),
		}

		cmd := NewDeleteBuildpack(ui, buildpackRepo)

		ctxt := testcmd.NewContext("delete-buildpack", []string{"my-buildpack"})
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(buildpackRepo.DeleteBuildpackGuid).To(Equal("my-buildpack-guid"))

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Deleting buildpack", "my-buildpack"},
			{"FAILED"},
			{"my-buildpack"},
			{"failed badly"},
		})
	})
	It("TestDeleteBuildpackForceFlagSkipsConfirmation", func() {

		ui := &testterm.FakeUI{}
		buildpack := models.Buildpack{}
		buildpack.Name = "my-buildpack"
		buildpack.Guid = "my-buildpack-guid"
		buildpackRepo := &testapi.FakeBuildpackRepository{
			FindByNameBuildpack: buildpack,
		}

		cmd := NewDeleteBuildpack(ui, buildpackRepo)

		ctxt := testcmd.NewContext("delete-buildpack", []string{"-f", "my-buildpack"})
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true}

		testcmd.RunCommand(cmd, ctxt, reqFactory)

		Expect(buildpackRepo.DeleteBuildpackGuid).To(Equal("my-buildpack-guid"))

		Expect(len(ui.Prompts)).To(Equal(0))
		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Deleting buildpack", "my-buildpack"},
			{"OK"},
		})
	})
})
