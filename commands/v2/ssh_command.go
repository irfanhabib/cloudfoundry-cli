package v2

import (
	"os"

	"code.cloudfoundry.org/cli/cf/cmd"
	"code.cloudfoundry.org/cli/commands/flags"
)

type SSHCommand struct {
	RequiredArgs        flags.AppName `positional-args:"yes"`
	LocalPort           string        `short:"L" description:"Local port forward specification. Local port forward specification. This flag can be defined more than once."`
	Command             string        `long:"command" short:"c" description:"Command to run. This flag can be defined more than once."`
	AppInstanceIndex    int           `long:"app-instance-index" short:"i" description:"Application instance index"`
	SkipHostValidation  bool          `long:"skip-host-validation" short:"k" description:"Skip host key validation"`
	SkipRemoteExecution bool          `long:"skip-remote-execution" short:"N" description:"Do not execute a remote command"`
	RemotePseudoTTY     bool          `long:"request-pseudo-tty" short:"t" description:"Request pseudo-tty allocation"`
	ForcePseudoTTY      bool          `long:"force-pseudo-tty" short:"F" description:"Force pseudo-tty allocation"`
	DisablePseudoTTY    bool          `long:"disable-pseudo-tty" short:"T" description:"Disable pseudo-tty allocation"`
}

func (_ SSHCommand) Execute(args []string) error {
	cmd.Main(os.Getenv("CF_TRACE"), os.Args)
	return nil
}
