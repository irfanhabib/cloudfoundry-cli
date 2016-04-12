package buildpack_test

import (
	"strings"

	"github.com/cloudfoundry/cli/cf"
	"github.com/cloudfoundry/cli/cf/api/apifakes"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	"github.com/cloudfoundry/cli/cf/commandregistry"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("create-buildpack command", func() {
	var (
		requirementsFactory *testreq.FakeReqFactory
		repo                *apifakes.OldFakeBuildpackRepository
		bitsRepo            *apifakes.OldFakeBuildpackBitsRepository
		ui                  *testterm.FakeUI
		deps                commandregistry.Dependency
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.Ui = ui
		deps.RepoLocator = deps.RepoLocator.SetBuildpackRepository(repo)
		deps.RepoLocator = deps.RepoLocator.SetBuildpackBitsRepository(bitsRepo)
		commandregistry.Commands.SetCommand(commandregistry.Commands.FindCommand("create-buildpack").SetDependency(deps, pluginCall))
	}

	BeforeEach(func() {
		requirementsFactory = &testreq.FakeReqFactory{LoginSuccess: true}
		repo = new(apifakes.OldFakeBuildpackRepository)
		bitsRepo = new(apifakes.OldFakeBuildpackBitsRepository)
		ui = &testterm.FakeUI{}
	})

	It("fails requirements when the user is not logged in", func() {
		requirementsFactory.LoginSuccess = false
		Expect(testcmd.RunCliCommand("create-buildpack", []string{"my-buildpack", "my-dir", "0"}, requirementsFactory, updateCommandDependency, false)).To(BeFalse())
	})

	It("fails with usage when given fewer than three arguments", func() {
		testcmd.RunCliCommand("create-buildpack", []string{}, requirementsFactory, updateCommandDependency, false)
		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Incorrect Usage", "Requires", "arguments"},
		))
	})

	It("creates and uploads buildpacks", func() {
		testcmd.RunCliCommand("create-buildpack", []string{"my-buildpack", "my.war", "5"}, requirementsFactory, updateCommandDependency, false)

		Expect(repo.CreateBuildpack.Enabled).To(BeNil())
		Expect(strings.HasSuffix(bitsRepo.UploadBuildpackPath, "my.war")).To(Equal(true))
		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Creating buildpack", "my-buildpack"},
			[]string{"OK"},
			[]string{"Uploading buildpack", "my-buildpack"},
			[]string{"OK"},
		))
		Expect(ui.Outputs).ToNot(ContainSubstrings([]string{"FAILED"}))
	})

	It("warns the user when the buildpack already exists", func() {
		repo.CreateBuildpackExists = true
		testcmd.RunCliCommand("create-buildpack", []string{"my-buildpack", "my.war", "5"}, requirementsFactory, updateCommandDependency, false)

		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Creating buildpack", "my-buildpack"},
			[]string{"OK"},
			[]string{"my-buildpack", "already exists"},
			[]string{"TIP", "use", cf.Name, "update-buildpack"},
		))
		Expect(ui.Outputs).ToNot(ContainSubstrings([]string{"FAILED"}))
	})

	It("enables the buildpack when given the --enabled flag", func() {
		testcmd.RunCliCommand("create-buildpack", []string{"--enable", "my-buildpack", "my.war", "5"}, requirementsFactory, updateCommandDependency, false)

		Expect(*repo.CreateBuildpack.Enabled).To(Equal(true))
	})

	It("disables the buildpack when given the --disable flag", func() {
		testcmd.RunCliCommand("create-buildpack", []string{"--disable", "my-buildpack", "my.war", "5"}, requirementsFactory, updateCommandDependency, false)

		Expect(*repo.CreateBuildpack.Enabled).To(Equal(false))
	})

	It("alerts the user when uploading the buildpack bits fails", func() {
		bitsRepo.UploadBuildpackErr = true
		testcmd.RunCliCommand("create-buildpack", []string{"my-buildpack", "bogus/path", "5"}, requirementsFactory, updateCommandDependency, false)

		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Creating buildpack", "my-buildpack"},
			[]string{"OK"},
			[]string{"Uploading buildpack"},
			[]string{"FAILED"},
		))
	})
})
