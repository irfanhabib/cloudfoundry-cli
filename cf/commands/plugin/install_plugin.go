package plugin

import (
	"errors"
	"fmt"
	"net/rpc"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cloudfoundry/cli/cf/actors/plugin_repo"
	"github.com/cloudfoundry/cli/cf/command_registry"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/configuration/plugin_config"
	. "github.com/cloudfoundry/cli/cf/i18n"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/cloudfoundry/cli/fileutils"
	"github.com/cloudfoundry/cli/flags"
	"github.com/cloudfoundry/cli/flags/flag"
	"github.com/cloudfoundry/cli/plugin"
	"github.com/cloudfoundry/cli/utils"

	clipr "github.com/cloudfoundry-incubator/cli-plugin-repo/models"
	rpcService "github.com/cloudfoundry/cli/plugin/rpc"
)

type PluginInstall struct {
	ui           terminal.UI
	config       core_config.Reader
	pluginConfig plugin_config.PluginConfiguration
	pluginRepo   plugin_repo.PluginRepo
	checksum     utils.Sha1Checksum
	rpcService   *rpcService.CliRpcService
}

type PluginInstaller interface {
	Install(inputSourceFilepath string) string
}

type PluginDownloader struct {
	ui             terminal.UI
	fileDownloader fileutils.Downloader
}

type InstallerContext struct {
	pluginDownloader *PluginDownloader
	repoName         string
	checksummer      utils.Sha1Checksum
	pluginRepo       plugin_repo.PluginRepo
	ui               terminal.UI
	getPluginRepos   pluginReposFetcher
}

type pluginReposFetcher func() []models.PluginRepo
type downloadFromPath func(pluginSourceFilepath string, downloader fileutils.Downloader) string

type PluginInstallerWithRepo struct {
	ui               terminal.UI
	pluginDownloader *PluginDownloader
	downloadFromPath downloadFromPath
	repoName         string
	checksummer      utils.Sha1Checksum
	pluginRepo       plugin_repo.PluginRepo
	getPluginRepos   pluginReposFetcher
}

type PluginInstallerWithoutRepo struct {
	ui               terminal.UI
	pluginDownloader *PluginDownloader
	downloadFromPath downloadFromPath
	repoName         string
}

func init() {
	command_registry.Register(&PluginInstall{})
}

func (cmd *PluginInstall) MetaData() command_registry.CommandMetadata {
	fs := make(map[string]flags.FlagSet)
	fs["r"] = &cliFlags.StringFlag{Name: "r", Usage: T("repo name where the plugin binary is located")}

	return command_registry.CommandMetadata{
		Name:        "install-plugin",
		Description: T("Install the plugin defined in command argument"),
		Usage: T(`CF_NAME install-plugin URL or LOCAL-PATH/TO/PLUGIN [-r REPO_NAME]

The command will download the plugin binary from repository if '-r' is provided

EXAMPLE:
   cf install-plugin https://github.com/cf-experimental/plugin-foobar
   cf install-plugin ~/Downloads/plugin-foobar
   cf install-plugin plugin-echo -r My-Repo 
`),
		Flags:     fs,
		TotalArgs: 1,
	}
}

func (cmd *PluginInstall) Requirements(requirementsFactory requirements.Factory, fc flags.FlagContext) (reqs []requirements.Requirement, err error) {
	if len(fc.Args()) != 1 {
		cmd.ui.Failed(T("Incorrect Usage. Requires an argument\n\n") + command_registry.Commands.CommandUsage("install-plugin"))
	}

	return
}

func (cmd *PluginInstall) SetDependency(deps command_registry.Dependency, pluginCall bool) command_registry.Command {
	cmd.ui = deps.Ui
	cmd.config = deps.Config
	cmd.pluginConfig = deps.PluginConfig
	cmd.pluginRepo = deps.PluginRepo
	cmd.checksum = deps.ChecksumUtil

	//reset rpc registration in case there is other running instance,
	//each service can only be registered once
	rpc.DefaultServer = rpc.NewServer()

	rpcService, err := rpcService.NewRpcService(deps.TeePrinter, deps.TeePrinter, deps.Config, deps.RepoLocator, rpcService.NewNonCodegangstaRunner())
	if err != nil {
		cmd.ui.Failed("Error initializing RPC service: " + err.Error())
	}

	cmd.rpcService = rpcService

	return cmd
}

func (installer *PluginInstallerWithoutRepo) Install(inputSourceFilepath string) (outputSourceFilepath string) {
	if filepath.Dir(inputSourceFilepath) == "." {
		outputSourceFilepath = "./" + filepath.Clean(inputSourceFilepath)
	} else {
		outputSourceFilepath = inputSourceFilepath
	}

	installer.ui.Say("")
	if strings.HasPrefix(outputSourceFilepath, "https://") || strings.HasPrefix(outputSourceFilepath, "http://") ||
		strings.HasPrefix(outputSourceFilepath, "ftp://") || strings.HasPrefix(outputSourceFilepath, "ftps://") {
		installer.ui.Say(T("Attempting to download binary file from internet address..."))
		return installer.pluginDownloader.downloadFromPath(outputSourceFilepath)
	} else if !installer.ensureCandidatePluginBinaryExistsAtGivenPath(outputSourceFilepath) {
		installer.ui.Failed(T("File not found locally, make sure the file exists at given path {{.filepath}}", map[string]interface{}{"filepath": outputSourceFilepath}))
	}

	return outputSourceFilepath
}

func (installer *PluginInstallerWithRepo) Install(inputSourceFilepath string) (outputSourceFilepath string) {
	targetPluginName := strings.ToLower(inputSourceFilepath)

	installer.ui.Say(T("Looking up '{{.filePath}}' from repository '{{.repoName}}'", map[string]interface{}{"filePath": inputSourceFilepath, "repoName": installer.repoName}))

	repoModel, err := installer.getRepoFromConfig(installer.repoName)
	if err != nil {
		installer.ui.Failed(err.Error() + "\n" + T("Tip: use 'add-plugin-repo' to register the repo"))
	}

	pluginList, repoAry := installer.pluginRepo.GetPlugins([]models.PluginRepo{repoModel})
	if len(repoAry) != 0 {
		installer.ui.Failed(T("Error getting plugin metadata from repo: ") + repoAry[0])
	}

	found := false
	sha1 := ""
	for _, plugin := range findRepoCaseInsensity(pluginList, installer.repoName) {
		if strings.ToLower(plugin.Name) == targetPluginName {
			found = true
			outputSourceFilepath, sha1 = installer.pluginDownloader.downloadFromPlugin(plugin)

			installer.checksummer.SetFilePath(outputSourceFilepath)
			if !installer.checksummer.CheckSha1(sha1) {
				installer.ui.Failed(T("Downloaded plugin binary's checksum does not match repo metadata"))
			}
		}

	}
	if !found {
		installer.ui.Failed(inputSourceFilepath + T(" is not available in repo '") + installer.repoName + "'")
	}

	return outputSourceFilepath
}

func NewPluginInstaller(context *InstallerContext) (installer PluginInstaller) {
	if context.repoName == "" {
		installer = &PluginInstallerWithoutRepo{
			ui:               context.ui,
			pluginDownloader: context.pluginDownloader,
			repoName:         context.repoName,
		}
	} else {
		installer = &PluginInstallerWithRepo{
			ui:               context.ui,
			pluginDownloader: context.pluginDownloader,
			repoName:         context.repoName,
			checksummer:      context.checksummer,
			pluginRepo:       context.pluginRepo,
			getPluginRepos:   context.getPluginRepos,
		}
	}
	return installer
}

func (cmd *PluginInstall) Execute(c flags.FlagContext) {
	fileDownloader := fileutils.NewDownloader(os.TempDir())

	removeTmpFile := func() {
		err := fileDownloader.RemoveFile()
		if err != nil {
			cmd.ui.Say(T("Problem removing downloaded binary in temp directory: ") + err.Error())
		}
	}
	defer removeTmpFile()

	deps := &InstallerContext{
		checksummer:      cmd.checksum,
		getPluginRepos:   cmd.config.PluginRepos,
		pluginDownloader: &PluginDownloader{cmd.ui, fileDownloader},
		pluginRepo:       cmd.pluginRepo,
		repoName:         c.String("r"),
		ui:               cmd.ui,
	}
	installer := NewPluginInstaller(deps)
	pluginSourceFilepath := installer.Install(c.Args()[0])

	cmd.ui.Say(fmt.Sprintf(T("Installing plugin {{.PluginPath}}...", map[string]interface{}{"PluginPath": pluginSourceFilepath})))

	_, pluginExecutableName := filepath.Split(pluginSourceFilepath)

	pluginDestinationFilepath := filepath.Join(cmd.pluginConfig.GetPluginPath(), pluginExecutableName)

	cmd.ensurePluginBinaryWithSameFileNameDoesNotAlreadyExist(pluginDestinationFilepath, pluginExecutableName)

	pluginMetadata := cmd.runBinaryAndObtainPluginMetadata(pluginSourceFilepath)

	cmd.ensurePluginIsSafeForInstallation(pluginMetadata, pluginDestinationFilepath, pluginSourceFilepath)

	cmd.installPlugin(pluginMetadata, pluginDestinationFilepath, pluginSourceFilepath)

	cmd.ui.Ok()
	cmd.ui.Say(fmt.Sprintf(T("Plugin {{.PluginName}} v{{.Version}} successfully installed.", map[string]interface{}{"PluginName": pluginMetadata.Name, "Version": fmt.Sprintf("%d.%d.%d", pluginMetadata.Version.Major, pluginMetadata.Version.Minor, pluginMetadata.Version.Build)})))
}

func (cmd *PluginInstall) ensurePluginBinaryWithSameFileNameDoesNotAlreadyExist(pluginDestinationFilepath, pluginExecutableName string) {
	_, err := os.Stat(pluginDestinationFilepath)
	if err == nil || os.IsExist(err) {
		cmd.ui.Failed(fmt.Sprintf(T("The file {{.PluginExecutableName}} already exists under the plugin directory.\n",
			map[string]interface{}{
				"PluginExecutableName": pluginExecutableName,
			})))
	} else if !os.IsNotExist(err) {
		cmd.ui.Failed(fmt.Sprintf(T("Unexpected error has occurred:\n{{.Error}}", map[string]interface{}{"Error": err.Error()})))
	}
}

func (cmd *PluginInstall) ensurePluginIsSafeForInstallation(pluginMetadata *plugin.PluginMetadata, pluginDestinationFilepath string, pluginSourceFilepath string) {
	plugins := cmd.pluginConfig.Plugins()
	if pluginMetadata.Name == "" {
		cmd.ui.Failed(fmt.Sprintf(T("Unable to obtain plugin name for executable {{.Executable}}", map[string]interface{}{"Executable": pluginSourceFilepath})))
	}

	if _, ok := plugins[pluginMetadata.Name]; ok {
		cmd.ui.Failed(fmt.Sprintf(T("Plugin name {{.PluginName}} is already taken", map[string]interface{}{"PluginName": pluginMetadata.Name})))
	}

	if pluginMetadata.Commands == nil {
		cmd.ui.Failed(fmt.Sprintf(T("Error getting command list from plugin {{.FilePath}}", map[string]interface{}{"FilePath": pluginSourceFilepath})))
	}

	for _, pluginCmd := range pluginMetadata.Commands {

		//check for command conflicting core commands/alias
		if pluginCmd.Name == "help" || command_registry.Commands.CommandExists(pluginCmd.Name) {
			cmd.ui.Failed(fmt.Sprintf(T("Command `{{.Command}}` in the plugin being installed is a native CF command/alias.  Rename the `{{.Command}}` command in the plugin being installed in order to enable its installation and use.",
				map[string]interface{}{"Command": pluginCmd.Name})))
		}

		//check for alias conflicting core command/alias
		if pluginCmd.Alias == "help" || command_registry.Commands.CommandExists(pluginCmd.Alias) {
			cmd.ui.Failed(fmt.Sprintf(T("Alias `{{.Command}}` in the plugin being installed is a native CF command/alias.  Rename the `{{.Command}}` command in the plugin being installed in order to enable its installation and use.",
				map[string]interface{}{"Command": pluginCmd.Alias})))
		}

		for installedPluginName, installedPlugin := range plugins {
			for _, installedPluginCmd := range installedPlugin.Commands {

				//check for command conflicting other plugin commands/alias
				if installedPluginCmd.Name == pluginCmd.Name || installedPluginCmd.Alias == pluginCmd.Name {
					cmd.ui.Failed(fmt.Sprintf(T("Command `{{.Command}}` is a command/alias in plugin '{{.PluginName}}'.  You could try uninstalling plugin '{{.PluginName}}' and then install this plugin in order to invoke the `{{.Command}}` command.  However, you should first fully understand the impact of uninstalling the existing '{{.PluginName}}' plugin.",
						map[string]interface{}{"Command": pluginCmd.Name, "PluginName": installedPluginName})))
				}

				//check for alias conflicting other plugin commands/alias
				if pluginCmd.Alias != "" && (installedPluginCmd.Name == pluginCmd.Alias || installedPluginCmd.Alias == pluginCmd.Alias) {
					cmd.ui.Failed(fmt.Sprintf(T("Alias `{{.Command}}` is a command/alias in plugin '{{.PluginName}}'.  You could try uninstalling plugin '{{.PluginName}}' and then install this plugin in order to invoke the `{{.Command}}` command.  However, you should first fully understand the impact of uninstalling the existing '{{.PluginName}}' plugin.",
						map[string]interface{}{"Command": pluginCmd.Alias, "PluginName": installedPluginName})))
				}
			}
		}
	}

}

func (cmd *PluginInstall) installPlugin(pluginMetadata *plugin.PluginMetadata, pluginDestinationFilepath, pluginSourceFilepath string) {
	err := fileutils.CopyFile(pluginDestinationFilepath, pluginSourceFilepath)
	if err != nil {
		cmd.ui.Failed(fmt.Sprintf(T("Could not copy plugin binary: \n{{.Error}}", map[string]interface{}{"Error": err.Error()})))
	}

	configMetadata := plugin_config.PluginMetadata{
		Location: pluginDestinationFilepath,
		Version:  pluginMetadata.Version,
		Commands: pluginMetadata.Commands,
	}

	cmd.pluginConfig.SetPlugin(pluginMetadata.Name, configMetadata)
}

func (installer *PluginInstallerWithoutRepo) ensureCandidatePluginBinaryExistsAtGivenPath(pluginSourceFilepath string) bool {
	_, err := os.Stat(pluginSourceFilepath)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func (downloader *PluginDownloader) downloadFromPath(pluginSourceFilepath string) string {
	size, filename, err := downloader.fileDownloader.DownloadFile(pluginSourceFilepath)

	if err != nil {
		downloader.ui.Failed(fmt.Sprintf(T("Download attempt failed: {{.Error}}\n\nUnable to install, plugin is not available from the given url.", map[string]interface{}{"Error": err.Error()})))
	}

	downloader.ui.Say(fmt.Sprintf("%d "+T("bytes downloaded")+"...", size))

	executablePath := filepath.Join(downloader.fileDownloader.SavePath(), filename)
	os.Chmod(executablePath, 0700)

	return executablePath
}

func (installer *PluginInstallerWithRepo) getRepoFromConfig(repoName string) (models.PluginRepo, error) {
	targetRepo := strings.ToLower(repoName)
	list := installer.getPluginRepos()

	for i, repo := range list {
		if strings.ToLower(repo.Name) == targetRepo {
			return list[i], nil
		}
	}

	return models.PluginRepo{}, errors.New(repoName + T(" not found"))
}

func (downloader *PluginDownloader) downloadFromPlugin(plugin clipr.Plugin) (string, string) {
	arch := runtime.GOARCH

	switch runtime.GOOS {
	case "darwin":
		return downloader.downloadFromPath(downloader.getBinaryUrl(plugin, "osx")), downloader.getBinaryChecksum(plugin, "osx")
	case "linux":
		if arch == "386" {
			return downloader.downloadFromPath(downloader.getBinaryUrl(plugin, "linux32")), downloader.getBinaryChecksum(plugin, "linux32")
		} else {
			return downloader.downloadFromPath(downloader.getBinaryUrl(plugin, "linux64")), downloader.getBinaryChecksum(plugin, "linux64")
		}
	case "windows":
		if arch == "386" {
			return downloader.downloadFromPath(downloader.getBinaryUrl(plugin, "win32")), downloader.getBinaryChecksum(plugin, "win32")
		} else {
			return downloader.downloadFromPath(downloader.getBinaryUrl(plugin, "win64")), downloader.getBinaryChecksum(plugin, "win64")
		}
	default:
		downloader.binaryNotAvailable()
	}
	return "", ""
}

func (downloader *PluginDownloader) getBinaryUrl(plugin clipr.Plugin, os string) string {
	for _, binary := range plugin.Binaries {
		if binary.Platform == os {
			return binary.Url
		}
	}
	downloader.binaryNotAvailable()
	return ""
}

func (downloader *PluginDownloader) getBinaryChecksum(plugin clipr.Plugin, os string) string {
	for _, binary := range plugin.Binaries {
		if binary.Platform == os {
			return binary.Checksum
		}
	}
	return ""
}

func (downloader *PluginDownloader) binaryNotAvailable() {
	downloader.ui.Failed(T("Plugin requested has no binary available for your OS: ") + runtime.GOOS + ", " + runtime.GOARCH)
}

func (cmd *PluginInstall) runBinaryAndObtainPluginMetadata(pluginSourceFilepath string) *plugin.PluginMetadata {
	err := cmd.rpcService.Start()
	if err != nil {
		cmd.ui.Failed(err.Error())
	}
	defer cmd.rpcService.Stop()

	cmd.runPluginBinary(pluginSourceFilepath, cmd.rpcService.Port())

	return cmd.rpcService.RpcCmd.PluginMetadata
}

func (cmd *PluginInstall) runPluginBinary(location string, servicePort string) {
	pluginInvocation := exec.Command(location, servicePort, "SendMetadata")

	err := pluginInvocation.Run()
	if err != nil {
		cmd.ui.Failed(err.Error())
	}
}

func findRepoCaseInsensity(repoList map[string][]clipr.Plugin, repoName string) []clipr.Plugin {
	target := strings.ToLower(repoName)
	for k, repo := range repoList {
		if strings.ToLower(k) == target {
			return repo
		}
	}
	return nil
}
