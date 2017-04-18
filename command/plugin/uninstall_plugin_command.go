package plugin

import (
	"code.cloudfoundry.org/cli/actor/pluginaction"
	"code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/command/flag"
	"code.cloudfoundry.org/cli/command/plugin/shared"
)

//go:generate counterfeiter . UninstallPluginActor

type UninstallPluginActor interface {
	UninstallPlugin(pluginaction.PluginUninstaller, string) error
}

type UninstallPluginCommand struct {
	RequiredArgs    flag.PluginName `positional-args:"yes"`
	usage           interface{}     `usage:"CF_NAME uninstall-plugin PLUGIN-NAME"`
	relatedCommands interface{}     `related_commands:"plugins"`

	Config command.Config
	UI     command.UI
	Actor  UninstallPluginActor
}

func (cmd *UninstallPluginCommand) Setup(config command.Config, ui command.UI) error {
	cmd.Config = config
	cmd.UI = ui
	cmd.Actor = pluginaction.NewActor(config)
	return nil
}

func (cmd UninstallPluginCommand) Execute(args []string) error {
	pluginName := cmd.RequiredArgs.PluginName
	plugin, exist := cmd.Config.Plugins()[pluginName]
	if !exist {
		return shared.PluginNotFoundError{Name: pluginName}
	}

	cmd.UI.DisplayTextWithFlavor("Uninstalling plugin {{.PluginName}}...",
		map[string]interface{}{
			"PluginName": pluginName,
		})

	err := cmd.Actor.UninstallPlugin(shared.NewPluginUninstaller(cmd.Config, cmd.UI), pluginName)
	if err != nil {
		return shared.HandleError(err)
	}

	cmd.UI.DisplayOK()
	cmd.UI.DisplayText("Plugin {{.PluginName}} {{.PluginVersion}} successfully uninstalled.",
		map[string]interface{}{
			"PluginName":    pluginName,
			"PluginVersion": plugin.Version,
		})

	return nil
}
