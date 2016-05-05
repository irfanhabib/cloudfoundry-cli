package help_test

import (
	"path/filepath"
	"strings"

	"github.com/cloudfoundry/cli/cf/commandregistry"
	"github.com/cloudfoundry/cli/cf/configuration/confighelpers"
	"github.com/cloudfoundry/cli/cf/help"

	"github.com/cloudfoundry/cli/testhelpers/io"

	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Help", func() {
	var buffer *gbytes.Buffer
	BeforeEach(func() {
		buffer = gbytes.NewBuffer()
	})

	It("shows help for all commands", func() {
		dummyTemplate := `
{{range .Commands}}{{range .CommandSubGroups}}{{range .}}
{{.Name}}
{{end}}{{end}}{{end}}
`
		help.ShowHelp(buffer, dummyTemplate)

		Expect(buffer).To(gbytes.Say("login"))
		for _, metadata := range commandregistry.Commands.Metadatas() {
			if metadata.Hidden {
				continue
			}
			Expect(buffer.Contents()).To(ContainSubstring(metadata.Name))
		}
	})

	It("shows help for all installed plugin's commands", func() {
		confighelpers.PluginRepoDir = func() string {
			return filepath.Join("..", "..", "fixtures", "config", "help-plugin-test-config")
		}

		dummyTemplate := `
{{range .Commands}}{{range .CommandSubGroups}}{{range .}}
{{.Name}}
{{end}}{{end}}{{end}}
`
		help.ShowHelp(buffer, dummyTemplate)
		Expect(buffer).To(gbytes.Say("test1_cmd2"))
		Expect(buffer).To(gbytes.Say("test2_cmd1"))
		Expect(buffer).To(gbytes.Say("test2_cmd2"))
		Expect(buffer).To(gbytes.Say("test2_really_long_really_long_really_long_command_name"))
	})

	It("adjusts the output format to the longest length of plugin command name", func() {
		confighelpers.PluginRepoDir = func() string {
			return filepath.Join("..", "..", "fixtures", "config", "help-plugin-test-config")
		}

		dummyTemplate := `
{{range .Commands}}{{range .CommandSubGroups}}{{range .}}
{{.Name}}%%%{{.Description}}
{{end}}{{end}}{{end}}
`
		output := io.CaptureOutput(func() {
			help.ShowHelp(os.Stdout, dummyTemplate)
		})

		cmdNameLen := len(strings.Split(output[2], "%%%")[0])

		for _, line := range output {
			if strings.TrimSpace(line) == "" {
				continue
			}

			expectedLen := len(strings.Split(line, "%%%")[0])
			Expect(cmdNameLen).To(Equal(expectedLen))
		}

	})

	It("does not show command's alias in help for installed plugin", func() {
		confighelpers.PluginRepoDir = func() string {
			return filepath.Join("..", "..", "fixtures", "config", "help-plugin-test-config")
		}

		dummyTemplate := `
{{range .Commands}}{{range .CommandSubGroups}}{{range .}}
{{.Name}}
{{end}}{{end}}{{end}}
`
		help.ShowHelp(buffer, dummyTemplate)
		Expect(buffer).ToNot(gbytes.Say("test1_cmd1_alias"))
	})
})
