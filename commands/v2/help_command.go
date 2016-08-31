package v2

import (
	"fmt"
	"strings"

	"code.cloudfoundry.org/cli/actors/v2actions"
	"code.cloudfoundry.org/cli/cf"
	"code.cloudfoundry.org/cli/commands"
	"code.cloudfoundry.org/cli/commands/flags"
	"code.cloudfoundry.org/cli/commands/ui"
	"code.cloudfoundry.org/cli/commands/v2/internal"
	"code.cloudfoundry.org/cli/utils/config"
)

const (
	CF_NAME = "cf"
)

//go:generate counterfeiter . HelpActor

// HelpActor handles the business logic of the help command
type HelpActor interface {
	// GetCommandInfo returns back a help command information for the given
	// command
	GetCommandInfo(interface{}, string) (v2actions.CommandInfo, error)

	// GetAllNamesAndDescriptions returns a list of all commands
	GetAllNamesAndDescriptions(interface{}) map[string]v2actions.CommandInfo
}

type HelpCommand struct {
	UI     UI
	Actor  HelpActor
	Config commands.Config

	OptionalArgs flags.CommandName `positional-args:"yes"`
	usage        interface{}       `usage:"CF_NAME help [COMMAND]"`
}

func (cmd *HelpCommand) Setup(config commands.Config) error {
	cmd.UI = ui.NewUI(config)
	cmd.Actor = v2actions.NewActor()
	cmd.Config = config
	return nil
}

func (cmd HelpCommand) Execute(args []string) error {
	var err error
	if cmd.OptionalArgs.CommandName == "" {
		cmd.displayFullHelp()
	} else {
		err = cmd.displayCommand()
	}

	return err
}

func (cmd HelpCommand) displayFullHelp() {
	cmd.displayHelpPreamble()
	cmd.displayAllCommands()
	cmd.displayHelpFooter()
}

func (cmd HelpCommand) displayHelpPreamble() {
	cmd.UI.DisplayHelpHeader("NAME:")
	cmd.UI.DisplayTextWithKeyTranslations("   {{.CommandName}} - {{.CommandDescription}}",
		[]string{"CommandDescription"},
		map[string]interface{}{
			"CommandName":        CF_NAME,
			"CommandDescription": "A command line tool to interact with Cloud Foundry",
		})
	cmd.UI.DisplayNewline()

	cmd.UI.DisplayHelpHeader("USAGE:")
	cmd.UI.DisplayTextWithKeyTranslations("   {{.CommandName}} {{.CommandUsage}}",
		[]string{"CommandUsage"},
		map[string]interface{}{
			"CommandName":  CF_NAME,
			"CommandUsage": "[global options] command [arguments...] [command options]",
		})
	cmd.UI.DisplayNewline()

	cmd.UI.DisplayHelpHeader("VERSION:")
	cmd.UI.DisplayText("   {{.Version}}-{{.Time}}", map[string]interface{}{
		"Version": cf.Version,
		"Time":    cf.BuiltOnDate,
	})
	cmd.UI.DisplayNewline()
}

func (cmd HelpCommand) displayAllCommands() {
	cmdInfo := cmd.Actor.GetAllNamesAndDescriptions(Commands)
	pluginCommands := []config.PluginCommand{}

	for _, pluginCommand := range cmd.Config.PluginConfig() {
		pluginCommands = append(pluginCommands, pluginCommand.Commands...)
	}
	longestCmd := internal.LongestCommandName(cmdInfo, pluginCommands)

	for _, category := range internal.HelpCategoryList {
		cmd.UI.DisplayHelpHeader(category.CategoryName)

		for _, command := range category.CommandList {
			if command == internal.BLANKLINE {
				cmd.UI.DisplayNewline()
				continue
			}

			cmd.UI.DisplayText("   {{.CommandName}}{{.Gap}}{{.CommandDescription}}", map[string]interface{}{
				"CommandName":        cmdInfo[command].Name,
				"CommandDescription": cmdInfo[command].Description,
				"Gap":                strings.Repeat(" ", longestCmd+1-len(command)),
			})
		}

		cmd.UI.DisplayNewline()
	}

	cmd.UI.DisplayHelpHeader("INSTALLED PLUGIN COMMANDS:")
	for _, pluginCommand := range pluginCommands {
		cmd.UI.DisplayText("   {{.CommandName}}{{.Gap}}{{.CommandDescription}}", map[string]interface{}{
			"CommandName":        pluginCommand.Name,
			"CommandDescription": pluginCommand.HelpText,
			"Gap":                strings.Repeat(" ", longestCmd+1-len(pluginCommand.Name)),
		})
	}
	cmd.UI.DisplayNewline()
}

func (cmd HelpCommand) displayHelpFooter() {
	cmd.UI.DisplayHelpHeader("ENVIRONMENT VARIABLES:")
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}                     {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_COLOR=false",
			"Description": "Do not colorize output",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}               {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_HOME=path/to/dir/",
			"Description": "Override path to default config directory",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}        {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_PLUGIN_HOME=path/to/dir/",
			"Description": "Override path to default plugin config director",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}              {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_STAGING_TIMEOUT=15",
			"Description": "Max wait time for buildpack staging, in minutes",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}               {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_STARTUP_TIMEOUT=5",
			"Description": "Max wait time for app instance startup, in minutes",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}                      {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_TRACE=true",
			"Description": "Print API request diagnostics to stdout",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}         {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "CF_TRACE=path/to/trace.log",
			"Description": "Append API request diagnostics to a log file",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}} {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "https_proxy=proxy.example.com:8080",
			"Description": "Enable HTTP proxying for API requests",
		})
	cmd.UI.DisplayNewline()

	cmd.UI.DisplayHelpHeader("GLOBAL OPTIONS:")
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}                         {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "--help, -h",
			"Description": "Show help",
		})
	cmd.UI.DisplayTextWithKeyTranslations("   {{.ENVName}}                                 {{.Description}}",
		[]string{"Description"},
		map[string]interface{}{
			"ENVName":     "-v",
			"Description": "Print API request diagnostics to stdout",
		})
}

func (cmd HelpCommand) displayCommand() error {
	cmdInfo, err := cmd.Actor.GetCommandInfo(Commands, cmd.OptionalArgs.CommandName)
	if err != nil {
		if err, ok := err.(v2actions.ErrorInvalidCommand); ok {
			var found bool
			if cmdInfo, found = cmd.findPlugin(); !found {
				return err
			}
		} else {
			return err
		}
	}

	cmd.UI.DisplayText("NAME:")
	cmd.UI.DisplayTextWithKeyTranslations("    {{.CommandName}} - {{.CommandDescription}}",
		[]string{"CommandDescription"},
		map[string]interface{}{
			"CommandName":        cmdInfo.Name,
			"CommandDescription": cmdInfo.Description,
		})
	cmd.UI.DisplayText("")

	//TODO: Figure out the best way to dynamically determine this
	usageString := strings.Replace(cmdInfo.Usage, "CF_NAME", CF_NAME, -1)
	cmd.UI.DisplayText("USAGE:")
	cmd.UI.DisplayTextWithKeyTranslations("    {{.CommandUsage}}",
		[]string{"CommandUsage"},
		map[string]interface{}{
			"CommandUsage": usageString,
		})
	cmd.UI.DisplayText("")

	if cmdInfo.Alias != "" {
		cmd.UI.DisplayText("ALIAS:")
		cmd.UI.DisplayText("    {{.Alias}}",
			map[string]interface{}{
				"Alias": cmdInfo.Alias,
			})
		cmd.UI.DisplayText("")
	}

	if len(cmdInfo.Flags) != 0 {
		cmd.UI.DisplayText("OPTIONS:")
		nameWidth := internal.LongestFlagWidth(cmdInfo.Flags) + 6
		for _, flag := range cmdInfo.Flags {
			var name string
			if flag.Short != "" && flag.Long != "" {
				name = fmt.Sprintf("--%s, -%s", flag.Long, flag.Short)
			} else if flag.Short != "" {
				name = "-" + flag.Short
			} else {
				name = "--" + flag.Long
			}

			cmd.UI.DisplayTextWithKeyTranslations("    {{.Flags}}{{.Spaces}}{{.Description}}",
				[]string{"Description"},
				map[string]interface{}{
					"Flags":       name,
					"Spaces":      strings.Repeat(" ", nameWidth-len(name)),
					"Description": flag.Description,
				})
		}
	}

	return nil
}

func (cmd HelpCommand) findPlugin() (v2actions.CommandInfo, bool) {
	for _, pluginConfig := range cmd.Config.PluginConfig() {
		for _, command := range pluginConfig.Commands {
			if command.Name == cmd.OptionalArgs.CommandName {
				return internal.ConvertPluginToCommandInfo(command), true
			}
		}
	}

	return v2actions.CommandInfo{}, false
}
