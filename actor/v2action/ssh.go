package v2action

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv2"
	"code.cloudfoundry.org/cli/util/clissh"
	"code.cloudfoundry.org/cli/util/clissh/sshterminal"
	"golang.org/x/crypto/ssh"
)

type SSHOptions struct {
	// Flag values
	ApplicationInstanceIndex uint
	Commands                 []string
	LocalPortForwarding      []string
	SkipHostValidation       bool
	SkipRemoteExecution      bool
	RequestPseudoTTY         bool
	ForcePseudoTTY           bool
	DisablePseudoTTY         bool

	// Parsed values
	TTYRequest            clissh.TTYRequest
	LocalPortForwardSpecs []clissh.LocalPortForward
}

func (actor Actor) GetSSHPasscode() (string, error) {
	return actor.UAAClient.GetSSHPasscode(actor.Config.AccessToken(), actor.Config.SSHOAuthClient())
}

func (actor Actor) RunSecureShell(appName string, spaceGUID string, sshOptions SSHOptions, ui UI) (Warnings, error) {
	err := sshOptions.parseLocalPortForwarding()
	if err != nil {
		return nil, err
	}

	switch {
	case sshOptions.DisablePseudoTTY:
		sshOptions.TTYRequest = clissh.RequestTTYNo
	case sshOptions.ForcePseudoTTY:
		sshOptions.TTYRequest = clissh.RequestTTYForce
	case sshOptions.RequestPseudoTTY:
		sshOptions.TTYRequest = clissh.RequestTTYYes
	default:
		sshOptions.TTYRequest = clissh.RequestTTYAuto
	}

	app, warnings, err := actor.GetApplicationByNameAndSpace(appName, spaceGUID)
	if err != nil {
		return warnings, err
	}

	if app.State != ccv2.ApplicationStarted {
		return warnings, fmt.Errorf("Application %q is not in the STARTED state", appName)
	}
	if !app.Diego {
		return warnings, fmt.Errorf("Application %q is not running on Diego", appName)
	}

	passcode, err := actor.GetSSHPasscode()
	if err != nil {
		return warnings, err
	}

	secureShell := clissh.NewSecureShell(
		clissh.DefaultSecureDialer(),
		sshterminal.DefaultHelper(),
		clissh.DefaultListenerFactory(),
		clissh.DefaultKeepAliveInterval,
	)

	err = secureShell.Connect(
		fmt.Sprintf("cf:%s/%d", app.GUID, sshOptions.ApplicationInstanceIndex),
		passcode,
		actor.CloudControllerClient.AppSSHEndpoint(),
		actor.CloudControllerClient.AppSSHHostKeyFingerprint(),
		sshOptions.SkipHostValidation,
	)
	if err != nil {
		return warnings, errors.New("Error opening SSH connection: " + err.Error())
	}
	defer secureShell.Close()

	err = secureShell.LocalPortForward(sshOptions.LocalPortForwardSpecs)
	if err != nil {
		return warnings, errors.New("Error forwarding port: " + err.Error())
	}

	if sshOptions.SkipRemoteExecution {
		err = secureShell.Wait()
	} else {
		err = secureShell.InteractiveSession(sshOptions.Commands, sshOptions.TTYRequest, ui.GetIn(), ui.GetOut(), ui.GetErr())
	}

	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			exitStatus := exitError.ExitStatus()
			if sig := exitError.Signal(); sig != "" {
				// TODO: create custom error
				return warnings, err
				// cmd.ui.Say(T("Process terminated by signal: {{.Signal}}. Exited with {{.ExitCode}}", map[string]interface{}{
				// 	"Signal":   sig,
				// 	"ExitCode": exitStatus,
				// }))
			}
			os.Exit(exitStatus)
		} else {
			return warnings, errors.New("Error: " + err.Error())
		}
	}
	return warnings, nil
}

func (o SSHOptions) parseLocalPortForwarding() error {
	for _, forwardStr := range o.LocalPortForwarding {
		forwardStr = strings.TrimSpace(forwardStr)

		parts := []string{}
		for remainder := forwardStr; remainder != ""; {
			part, r, err := tokenizeForward(remainder)
			if err != nil {
				return err
			}

			parts = append(parts, part)
			remainder = r
		}

		forwardSpec := clissh.LocalPortForward{}
		switch len(parts) {
		case 4:
			if parts[0] == "*" {
				parts[0] = ""
			}
			forwardSpec.ConnectAddress = fmt.Sprintf("%s:%s", parts[2], parts[3])
			forwardSpec.ListenAddress = fmt.Sprintf("%s:%s", parts[0], parts[1])
		case 3:
			forwardSpec.ConnectAddress = fmt.Sprintf("%s:%s", parts[1], parts[2])
			forwardSpec.ListenAddress = fmt.Sprintf("localhost:%s", parts[0])
		default:
			// TODO: return custom error type
			return fmt.Errorf("Unable to parse local forwarding argument: %q", forwardStr)
		}

		o.LocalPortForwardSpecs = append(o.LocalPortForwardSpecs, forwardSpec)
	}

	return nil
}

func tokenizeForward(arg string) (string, string, error) {
	switch arg[0] {
	case ':':
		return "", arg[1:], nil

	case '[':
		parts := strings.SplitAfterN(arg, "]", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("Argument missing closing bracket: %q", arg)
		}

		if parts[1][0] == ':' {
			return parts[0], parts[1][1:], nil
		}

		return "", "", fmt.Errorf("Unexpected token: %q", parts[1])

	default:
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) < 2 {
			return parts[0], "", nil
		}
		return parts[0], parts[1], nil
	}
}
