package v2action

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv2"
	"code.cloudfoundry.org/cli/util/clissh"
	"code.cloudfoundry.org/cli/util/clissh/sshterminal"
	"golang.org/x/crypto/ssh"
)

//go:generate counterfeiter . SecureShell

type SecureShell interface {
	Connect(username string, passcode string, appSSHEndpoint string, appSSHHostKeyFingerprint string, skipHostValidation bool) error
	InteractiveSession(commands []string, terminalRequest clissh.TTYRequest, stdin io.Reader, stdout io.Writer, stderr io.Writer) error
	LocalPortForward([]clissh.LocalPortForward) error
	Wait() error
	Close() error
}

type SSHOptions struct {
	ApplicationInstanceIndex uint
	Commands                 []string
	LocalPortForwardSpecs    []string
	SkipHostValidation       bool
	SkipRemoteExecution      bool
	RequestPseudoTTY         bool
	ForcePseudoTTY           bool
	DisablePseudoTTY         bool
}

func (actor Actor) GetSSHPasscode() (string, error) {
	return actor.UAAClient.GetSSHPasscode(actor.Config.AccessToken(), actor.Config.SSHOAuthClient())
}

func (actor Actor) RunSecureShell(appName string, spaceGUID string, sshOptions SSHOptions, ui UI) (Warnings, error) {
	app, warnings, err := actor.GetApplicationByNameAndSpace(appName, spaceGUID)
	if err != nil {
		return warnings, err
	}

	err = verifyApplicationSupportsSSH(sshOptions.ApplicationInstanceIndex, app)
	if err != nil {
		return warnings, err
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

	if len(sshOptions.LocalPortForwardSpecs) > 0 {
		err = handleLocalPortForwarding(sshOptions.LocalPortForwardSpecs, secureShell)
		if err != nil {
			return warnings, err
		}
	}

	if sshOptions.SkipRemoteExecution {
		// This will keep the connection alive until the user kills it eg. with crtl+c, usually used with local port forwarding
		err = secureShell.Wait()
	} else {
		err = secureShell.InteractiveSession(sshOptions.Commands, getTTYRequestType(sshOptions), ui.GetIn(), ui.GetOut(), ui.GetErr())
	}
	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			exitStatus := exitError.ExitStatus()
			if sig := exitError.Signal(); sig != "" {
				return warnings, fmt.Errorf("Process terminated by signal: {{.Signal}}. Exited with {{.ExitCode}}")
				// "Signal":   sig,
				// "ExitCode": exitStatus,
			}
			// TODO: propagate the exit status and handle it in main
			os.Exit(exitStatus)
		} else {
			return warnings, errors.New("Error: " + err.Error())
		}
	}
	return warnings, nil
}

func verifyApplicationSupportsSSH(appInstanceIndex uint, app Application) error {
	index := int(appInstanceIndex)
	if index > 0 && index >= app.Instances.Value {
		return fmt.Errorf("The specified application instance does not exist")
	}
	if app.State != ccv2.ApplicationStarted {
		return fmt.Errorf("Application %q is not in the STARTED state", app.Name)
	}
	if !app.Diego {
		return fmt.Errorf("Application %q is not running on Diego", app.Name)
	}
	return nil
}

func handleLocalPortForwarding(localPortForwardSpecs []string, secureShell SecureShell) error {
	localPortForwards, err := parseLocalPortForwardSpecs(localPortForwardSpecs)
	if err != nil {
		return err
	}

	err = secureShell.LocalPortForward(localPortForwards)
	if err != nil {
		return errors.New("Error forwarding port: " + err.Error())
	}
	return nil
}

func parseLocalPortForwardSpecs(localPortForwardSpecs []string) ([]clissh.LocalPortForward, error) {
	var localPortForwards []clissh.LocalPortForward

	for _, spec := range localPortForwardSpecs {
		spec = strings.TrimSpace(spec)
		parts := []string{}

		for remainder := spec; remainder != ""; {
			part, r, err := tokenizeForward(remainder)
			if err != nil {
				return nil, err
			}

			parts = append(parts, part)
			remainder = r
		}

		localPortForward := clissh.LocalPortForward{}
		switch len(parts) {
		case 4:
			if parts[0] == "*" {
				parts[0] = ""
			}
			localPortForward.ConnectAddress = fmt.Sprintf("%s:%s", parts[2], parts[3])
			localPortForward.ListenAddress = fmt.Sprintf("%s:%s", parts[0], parts[1])
		case 3:
			localPortForward.ConnectAddress = fmt.Sprintf("%s:%s", parts[1], parts[2])
			localPortForward.ListenAddress = fmt.Sprintf("localhost:%s", parts[0])
		default:
			// TODO: return custom error type
			return nil, fmt.Errorf("Unable to parse local forwarding argument: %q", spec)
		}
		localPortForwards = append(localPortForwards, localPortForward)
	}

	return localPortForwards, nil
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

func getTTYRequestType(sshOptions SSHOptions) clissh.TTYRequest {
	switch {
	case sshOptions.DisablePseudoTTY:
		return clissh.RequestTTYNo
	case sshOptions.ForcePseudoTTY:
		return clissh.RequestTTYForce
	case sshOptions.RequestPseudoTTY:
		return clissh.RequestTTYYes
	}
	return clissh.RequestTTYAuto
}
