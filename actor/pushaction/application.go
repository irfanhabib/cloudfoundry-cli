package pushaction

import (
	"fmt"

	"code.cloudfoundry.org/cli/actor/actionerror"
	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/types"
	log "github.com/sirupsen/logrus"
)

type Application struct {
	v2action.Application
	Buildpacks []types.FilteredString
	Stack      v2action.Stack
}

func (app Application) String() string {
	return fmt.Sprintf("%s, Stack Name: '%s'", app.Application, app.Stack.Name)
}

func (app *Application) SetStack(stack v2action.Stack) {
	app.Stack = stack
	app.StackGUID = stack.GUID
}

func (actor Actor) CreateApplication(config ApplicationConfig) (ApplicationConfig, Event, Warnings, error) {
	log.Debugf("creating application")
	v2App := config.DesiredApplication.Application
	v2App.Buildpack = actor.setBuildpack(config)

	newApp, warnings, err := actor.V2Actor.CreateApplication(v2App)
	if err != nil {
		log.Errorln("creating application:", err)
		return config, CreatedApplication, Warnings(warnings), err
	}

	config.DesiredApplication.Application = newApp
	config.CurrentApplication = config.DesiredApplication

	return config, CreatedApplication, Warnings(warnings), nil
}

func (actor Actor) UpdateApplication(config ApplicationConfig) (ApplicationConfig, Event, Warnings, error) {
	log.Debugf("updating application")
	v2App := config.DesiredApplication.Application
	v2App.Buildpack = actor.setBuildpack(config)

	v2App = actor.ignoreSameState(config, v2App)
	v2App = actor.ignoreSameStackGUID(config, v2App)

	v2App, warnings, err := actor.V2Actor.UpdateApplication(v2App)
	if err != nil {
		log.Errorln("updating application:", err)
		return ApplicationConfig{}, "", Warnings(warnings), err
	}

	config.DesiredApplication.Application = v2App
	config.CurrentApplication = config.DesiredApplication

	return config, UpdatedApplication, Warnings(warnings), err
}

func (actor Actor) FindOrReturnPartialApp(appName string, spaceGUID string) (bool, Application, v2action.Warnings, error) {
	foundApp, appWarnings, err := actor.V2Actor.GetApplicationByNameAndSpace(appName, spaceGUID)
	if _, ok := err.(actionerror.ApplicationNotFoundError); ok {
		log.Warnf("unable to find app %s in current space (GUID: %s)", appName, spaceGUID)
		return false, Application{
			Application: v2action.Application{
				Name:      appName,
				SpaceGUID: spaceGUID,
			},
		}, appWarnings, nil
	} else if err != nil {
		log.WithField("appName", appName).Error("error retrieving app")
		return false, Application{}, appWarnings, err
	}

	stack, stackWarnings, err := actor.V2Actor.GetStack(foundApp.StackGUID)
	warnings := append(appWarnings, stackWarnings...)
	if err != nil {
		log.Warnf("unable to find app's stack (GUID: %s)", foundApp.StackGUID)
		return false, Application{}, warnings, err
	}

	app := Application{
		Application: foundApp,
		Stack:       stack,
	}
	return true, app, warnings, err
}

// For some versions of CC, sending state will always result in CC
// attempting to do perform that request (i.e. started -> start/restart).
// In order to prevent repeated unintended restarts in the middle of a
// push, don't send state. This will be fixed in capi-release 1.48.0.
func (actor Actor) ignoreSameState(config ApplicationConfig, v2App v2action.Application) v2action.Application {
	if config.CurrentApplication.State == config.DesiredApplication.State {
		v2App.State = ""
	}

	return v2App
}

// Apps updates with both docker image and stack guids fail. So do not send
// StackGUID unless it is necessary.
func (actor Actor) ignoreSameStackGUID(config ApplicationConfig, v2App v2action.Application) v2action.Application {
	if config.CurrentApplication.StackGUID == config.DesiredApplication.StackGUID {
		v2App.StackGUID = ""
	}

	return v2App
}

func (actor Actor) setBuildpack(config ApplicationConfig) types.FilteredString {
	if len(config.DesiredApplication.Buildpacks) == 1 {
		return config.DesiredApplication.Buildpacks[0]
	}

	return config.DesiredApplication.Buildpack
}
