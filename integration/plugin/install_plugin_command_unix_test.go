// +build !windows

package plugin

import (
	"os"
	"path/filepath"

	"code.cloudfoundry.org/cli/integration/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = FDescribe("install-plugin command", func() {
	BeforeEach(func() {
		helpers.RunIfExperimental("experimental until all install-plugin refactor stories are finished")
	})

	Context("installing a plugin from a local file", func() {
		var pluginPath string

		BeforeEach(func() {
			pluginPath = helpers.BuildConfigurablePlugin("configurable_plugin", "some-plugin", "1.0.0",
				[]helpers.PluginCommand{
					{Name: "some-command", Help: "some-command-help"},
				},
			)
		})

		Context("when the -f flag is given", func() {
			It("sets the installed plugin's permissiont to 0755", func() {
				session := helpers.CF("install-plugin", pluginPath, "-f")
				Eventually(session).Should(Exit(0))

				installedPath := filepath.Join(homeDir, ".cf", "plugins", "some-plugin")
				stat, err := os.Stat(installedPath)
				Expect(err).ToNot(HaveOccurred())
				Expect(stat.Mode()).To(Equal(os.FileMode(0755)))
			})
		})
	})
})
