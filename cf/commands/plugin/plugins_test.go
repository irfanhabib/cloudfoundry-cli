package plugin_test

import (
	"net/rpc"

	. "github.com/cloudfoundry/cli/cf/commands/plugin"
	"github.com/cloudfoundry/cli/cf/configuration/plugin_config"
	testconfig "github.com/cloudfoundry/cli/cf/configuration/plugin_config/fakes"
	"github.com/cloudfoundry/cli/plugin"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Plugins", func() {
	var (
		ui                  *testterm.FakeUI
		requirementsFactory *testreq.FakeReqFactory
		config              *testconfig.FakePluginConfiguration
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		requirementsFactory = &testreq.FakeReqFactory{}
		config = &testconfig.FakePluginConfiguration{}

		rpc.DefaultServer = rpc.NewServer()
	})

	runCommand := func(args ...string) bool {
		cmd := NewPlugins(ui, config)
		return testcmd.RunCommand(cmd, args, requirementsFactory)
	}
	It("should fail with usage when provided any arguments", func() {
		requirementsFactory.LoginSuccess = true
		Expect(runCommand("blahblah")).To(BeFalse())
		Expect(ui.FailedWithUsage).To(BeTrue())
	})

	It("returns a list of available methods of a plugin", func() {
		config.PluginsReturns(map[string]plugin_config.PluginMetadata{
			"Test1": plugin_config.PluginMetadata{
				Location: "path/to/plugin",
				Commands: []plugin.Command{
					{Name: "test_1_cmd1", HelpText: "help text for test_1_cmd1"},
					{Name: "test_1_cmd2", HelpText: "help text for test_1_cmd2"},
				},
			},
		})

		runCommand()

		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Listing Installed Plugins..."},
			[]string{"OK"},
			[]string{"Plugin Name", "Command Name", "Command Help"},
			[]string{"Test1", "test_1_cmd1", "help text for test_1_cmd1"},
			[]string{"Test1", "test_1_cmd2", "help text for test_1_cmd2"},
		))
	})

	FIt("lists the name of the command and it's alias", func() {
		config.PluginsReturns(map[string]plugin_config.PluginMetadata{
			"Test1": plugin_config.PluginMetadata{
				Location: "path/to/plugin",
				Commands: []plugin.Command{
					{Name: "test_1_cmd1", Alias: "test_1_cmd1_alias", HelpText: "help text for test_1_cmd1"},
					{Name: "test_1_cmd2", Alias: "test_1_cmd2_alias", HelpText: "help text for test_1_cmd2"},
				},
			},
		})

		runCommand()

		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Test1", "test_1_cmd1", ", test_1_cmd1_alias", "help text for test_1_cmd1"},
			[]string{"Test1", "test_1_cmd2", ", test_1_cmd2_alias", "help text for test_1_cmd2"},
		))
	})

	It("does not list the plugin when it provides no available commands", func() {
		config.PluginsReturns(map[string]plugin_config.PluginMetadata{
			"EmptyPlugin": plugin_config.PluginMetadata{Location: "../../../fixtures/plugins/empty_plugin.exe"},
		})

		runCommand()
		Expect(ui.Outputs).NotTo(ContainSubstrings(
			[]string{"EmptyPlugin"},
		))
	})

	It("list multiple plugins and their associated commands", func() {
		config.PluginsReturns(map[string]plugin_config.PluginMetadata{
			"Test1": plugin_config.PluginMetadata{Location: "path/to/plugin1", Commands: []plugin.Command{{Name: "test_1_cmd1", HelpText: "help text for test_1_cmd1"}}},
			"Test2": plugin_config.PluginMetadata{Location: "path/to/plugin2", Commands: []plugin.Command{{Name: "test_2_cmd1", HelpText: "help text for test_2_cmd1"}}},
		})

		runCommand()
		Expect(ui.Outputs).To(ContainSubstrings(
			[]string{"Test1", "test_1_cmd1", "help text for test_1_cmd1"},
			[]string{"Test2", "test_2_cmd1", "help text for test_2_cmd1"},
		))
	})
})
