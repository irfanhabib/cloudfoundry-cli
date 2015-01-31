package plugin_repo

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cloudfoundry/cli/cf/command_metadata"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/codegangsta/cli"

	clipr "github.com/cloudfoundry-incubator/cli-plugin-repo/models"

	. "github.com/cloudfoundry/cli/cf/i18n"
)

type RepoPlugins struct {
	ui     terminal.UI
	config core_config.Reader
}

func NewRepoPlugins(ui terminal.UI, config core_config.Reader) RepoPlugins {
	return RepoPlugins{
		ui:     ui,
		config: config,
	}
}

func (cmd RepoPlugins) Metadata() command_metadata.CommandMetadata {
	return command_metadata.CommandMetadata{
		Name:        T("repo-plugins"),
		Description: T("List all available plugins in all added repositories"),
		Usage: T(`CF_NAME repo-plugins

EXAMPLE:
   cf repo-plugins
`),
	}
}

func (cmd RepoPlugins) GetRequirements(_ requirements.Factory, c *cli.Context) (req []requirements.Requirement, err error) {
	return
}

func (cmd RepoPlugins) Run(c *cli.Context) {
	repoError := []string{}
	var pluginList clipr.PluginsJson
	repoPlugins := make(map[string][]clipr.Plugin)

	repos := cmd.config.PluginRepos()

	cmd.ui.Say(T("Getting plugins from all repositories ... "))
	cmd.ui.Say("")
	for _, repo := range repos {
		resp, err := http.Get(getListEndpoint(repo.Url))
		if err != nil {
			repoError = append(repoError, fmt.Sprintf(T("Error requesting from")+" '%s' - %s", repo.Name, err.Error()))
			continue
		} else {
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				repoError = append(repoError, fmt.Sprintf(T("Error reading response from")+" '%s' - %s ", repo.Name, err.Error()))
				continue
			}

			pluginList = clipr.PluginsJson{Plugins: nil}
			err = json.Unmarshal(body, &pluginList)
			if err != nil {
				repoError = append(repoError, fmt.Sprintf(T("Invalid json data from")+" '%s' - %s", repo.Name, err.Error()))
				continue
			} else if pluginList.Plugins == nil {
				repoError = append(repoError, T("Invalid data from '{{.repoName}}' - plugin data does not exist", map[string]interface{}{"repoName": repo.Name}))
				continue
			}
		}

		repoPlugins[repo.Name] = pluginList.Plugins
	}

	cmd.printTable(repoPlugins)

	cmd.printErrors(repoError)
}

func (cmd RepoPlugins) printTable(repoPlugins map[string][]clipr.Plugin) {
	for k, plugins := range repoPlugins {
		cmd.ui.Say(terminal.ColorizeBold(T("Repository: ")+k, 33))
		table := cmd.ui.Table([]string{T("name"), T("version"), T("description")})
		for _, p := range plugins {
			table.Add(p.Name, p.Version, p.Description)
		}
		table.Print()
		cmd.ui.Say("")
	}
}

func (cmd RepoPlugins) printErrors(repoError []string) {
	if len(repoError) > 0 {
		cmd.ui.Say(terminal.ColorizeBold(T("Logged errors:"), 31))
		for _, e := range repoError {
			cmd.ui.Say(terminal.Colorize(e, 31))
		}
		cmd.ui.Say("")
	}
}

func getListEndpoint(url string) string {
	if strings.HasSuffix(url, "/") {
		return url + "list"
	}
	return url + "/list"
}
