package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/app"
	"github.com/cloudfoundry/cli/cf/command_factory"
	"github.com/cloudfoundry/cli/cf/command_metadata"
	"github.com/cloudfoundry/cli/cf/command_runner"
	"github.com/cloudfoundry/cli/cf/configuration/config_helpers"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/configuration/plugin_config"
	"github.com/cloudfoundry/cli/cf/flag_helpers"
	. "github.com/cloudfoundry/cli/cf/i18n"
	"github.com/cloudfoundry/cli/cf/i18n/detection"
	"github.com/cloudfoundry/cli/cf/manifest"
	"github.com/cloudfoundry/cli/cf/net"
	"github.com/cloudfoundry/cli/cf/panic_printer"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/cf/terminal"
	"github.com/cloudfoundry/cli/cf/trace"
	"github.com/cloudfoundry/cli/plugin/rpc"
	"github.com/codegangsta/cli"
)

var deps = setupDependencies()

type cliDependencies struct {
	termUI         terminal.UI
	configRepo     core_config.Repository
	pluginConfig   plugin_config.PluginConfiguration
	manifestRepo   manifest.ManifestRepository
	apiRepoLocator api.RepositoryLocator
	gateways       map[string]net.Gateway
	teePrinter     *terminal.TeePrinter
	detector       detection.Detector
}

func setupDependencies() (deps *cliDependencies) {
	deps = new(cliDependencies)

	deps.teePrinter = terminal.NewTeePrinter()

	deps.termUI = terminal.NewUI(os.Stdin, deps.teePrinter)

	deps.manifestRepo = manifest.NewManifestDiskRepository()

	errorHandler := func(err error) {
		if err != nil {
			deps.termUI.Failed(fmt.Sprintf("Config error: %s", err))
		}
	}
	deps.configRepo = core_config.NewRepositoryFromFilepath(config_helpers.DefaultFilePath(), errorHandler)
	deps.pluginConfig = plugin_config.NewPluginConfig(errorHandler)
	deps.detector = &detection.JibberJabberDetector{}

	T = Init(deps.configRepo, deps.detector)

	terminal.UserAskedForColors = deps.configRepo.ColorEnabled()
	terminal.InitColorSupport()

	if os.Getenv("CF_TRACE") != "" {
		trace.Logger = trace.NewLogger(os.Getenv("CF_TRACE"))
	} else {
		trace.Logger = trace.NewLogger(deps.configRepo.Trace())
	}

	deps.gateways = map[string]net.Gateway{
		"auth":             net.NewUAAGateway(deps.configRepo, deps.termUI),
		"cloud-controller": net.NewCloudControllerGateway(deps.configRepo, time.Now, deps.termUI),
		"uaa":              net.NewUAAGateway(deps.configRepo, deps.termUI),
	}
	deps.apiRepoLocator = api.NewRepositoryLocator(deps.configRepo, deps.gateways)

	return
}

func main() {
	defer handlePanics(deps.teePrinter)
	defer deps.configRepo.Close()

	cmdFactory := command_factory.NewFactory(deps.termUI, deps.configRepo, deps.manifestRepo, deps.apiRepoLocator, deps.pluginConfig)
	requirementsFactory := requirements.NewFactory(deps.termUI, deps.configRepo, deps.apiRepoLocator)
	cmdRunner := command_runner.NewRunner(cmdFactory, requirementsFactory, deps.termUI)
	pluginsConfig := plugin_config.NewPluginConfig(func(err error) { panic(err) })
	pluginList := pluginsConfig.Plugins()

	var badFlags string
	metaDatas := cmdFactory.CommandMetadatas()

	if len(os.Args) > 1 {
		flags, totalArgs := getCommandFlags(os.Args, metaDatas)

		if args2skip := totalArgs + 2; len(os.Args) >= args2skip {
			badFlags = matchArgAndFlags(flags, os.Args[args2skip:])
		}

		if badFlags != "" {
			badFlags = badFlags + "\n\n"
		}
	}

	injectHelpTemplate(badFlags)

	theApp := app.NewApp(cmdRunner, metaDatas...)
	//command `cf` without argument
	if len(os.Args) == 1 || os.Args[1] == "help" {
		theApp.Run(os.Args)
	} else if cmdFactory.CheckIfCoreCmdExists(os.Args[1]) {
		callCoreCommand(os.Args[0:], theApp)
	} else {
		// run each plugin and find the method/
		// run method if exist

		ran := rpc.RunMethodIfExists(theApp, os.Args[1:], deps.teePrinter, deps.teePrinter, pluginList)
		if !ran {
			theApp.Run(os.Args)
		}
	}
}

func gatewaySliceFromMap(gateway_map map[string]net.Gateway) []net.WarningProducer {
	gateways := []net.WarningProducer{}
	for _, gateway := range gateway_map {
		gateways = append(gateways, gateway)
	}
	return gateways
}

func injectHelpTemplate(badFlags string) {
	cli.CommandHelpTemplate = fmt.Sprintf(`%sNAME:
   {{.Name}} - {{.Description}}
{{with .ShortName}}
ALIAS:
   {{.}}
{{end}}
USAGE:
   {{.Usage}}{{with .Flags}}

OPTIONS:
{{range .}}   {{.}}
{{end}}{{else}}
{{end}}`, badFlags)
}

func handlePanics(printer terminal.Printer) {
	panic_printer.UI = terminal.NewUI(os.Stdin, printer)

	commandArgs := strings.Join(os.Args, " ")
	stackTrace := generateBacktrace()

	err := recover()
	panic_printer.DisplayCrashDialog(err, commandArgs, stackTrace)

	if err != nil {
		os.Exit(1)
	}
}

func generateBacktrace() string {
	stackByteCount := 0
	STACK_SIZE_LIMIT := 1024 * 1024
	var bytes []byte
	for stackSize := 1024; (stackByteCount == 0 || stackByteCount == stackSize) && stackSize < STACK_SIZE_LIMIT; stackSize = 2 * stackSize {
		bytes = make([]byte, stackSize)
		stackByteCount = runtime.Stack(bytes, true)
	}
	stackTrace := "\t" + strings.Replace(string(bytes), "\n", "\n\t", -1)
	return stackTrace
}

func callCoreCommand(args []string, theApp *cli.App) {
	err := theApp.Run(args)
	if err != nil {
		os.Exit(1)
	}
	gateways := gatewaySliceFromMap(deps.gateways)

	warningsCollector := net.NewWarningsCollector(deps.termUI, gateways...)
	warningsCollector.PrintWarnings()
}

func getCommandFlags(args []string, metaDatas []command_metadata.CommandMetadata) ([]string, int) {
	var flags []string
	var totalArgs int
	for _, cmd := range metaDatas {
		if args[1] == cmd.Name || args[1] == cmd.ShortName {
			totalArgs = cmd.TotalArgs
			for _, flag := range cmd.Flags {
				switch t := flag.(type) {
				default:
				case flag_helpers.StringSliceFlagWithNoDefault:
					flags = append(flags, t.Name)
				case flag_helpers.IntFlagWithNoDefault:
					flags = append(flags, t.Name)
				case flag_helpers.StringFlagWithNoDefault:
					flags = append(flags, t.Name)
				case cli.BoolFlag:
					flags = append(flags, t.Name)
				}
			}
		}
	}
	return flags, totalArgs
}

func matchArgAndFlags(flags []string, args []string) string {
	var badFlag string
	var lastPassed bool
	multipleFlagErr := false

Loop:
	for _, arg := range args {
		prefix := ""

		//only take flag name, ignore value after '='
		arg = strings.Split(arg, "=")[0]

		if arg == "--h" || arg == "-h" {
			continue Loop
		}

		if strings.HasPrefix(arg, "--") {
			prefix = "--"
		} else if strings.HasPrefix(arg, "-") {
			prefix = "-"
		}
		arg = strings.TrimLeft(arg, prefix)

		//skip verification for negative integers, e.g. -i -10
		if lastPassed {
			lastPassed = false
			if _, err := strconv.ParseInt(arg, 10, 32); err == nil {
				continue Loop
			}
		}

		if prefix != "" {
			for _, flag := range flags {
				if flag == arg {
					lastPassed = true
					continue Loop
				}
			}

			if badFlag == "" {
				badFlag = fmt.Sprintf("\"%s%s\"", prefix, arg)
			} else {
				multipleFlagErr = true
				badFlag = badFlag + fmt.Sprintf(", \"%s%s\"", prefix, arg)
			}
		}
	}

	if multipleFlagErr && badFlag != "" {
		badFlag = fmt.Sprintf("%s %s", T("Unknown flags:"), badFlag)
	} else if badFlag != "" {
		badFlag = fmt.Sprintf("%s %s", T("Unknown flag"), badFlag)
	}

	return badFlag
}
