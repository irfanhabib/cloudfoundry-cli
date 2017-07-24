package pushaction

import (
	"os"
	"path/filepath"

	"code.cloudfoundry.org/cli/actor/pushaction/manifest"
	"code.cloudfoundry.org/cli/actor/v2action"
	log "github.com/sirupsen/logrus"
)

type ApplicationConfig struct {
	CurrentApplication Application
	DesiredApplication Application

	CurrentRoutes []v2action.Route
	DesiredRoutes []v2action.Route

	AllResources       []v2action.Resource
	MatchedResources   []v2action.Resource
	UnmatchedResources []v2action.Resource
	Archive            bool
	Path               string

	TargetedSpaceGUID string
}

func (config ApplicationConfig) CreatingApplication() bool {
	return config.CurrentApplication.GUID == ""
}

func (config ApplicationConfig) UpdatingApplication() bool {
	return !config.CreatingApplication()
}

func (actor Actor) ConvertToApplicationConfigs(orgGUID string, spaceGUID string, apps []manifest.Application) ([]ApplicationConfig, Warnings, error) {
	var configs []ApplicationConfig
	var warnings Warnings

	log.Infof("iterating through %d app configuration(s)", len(apps))
	for _, app := range apps {
		absPath, err := filepath.EvalSymlinks(app.Path)
		if err != nil {
			return nil, nil, err
		}

		config := ApplicationConfig{
			TargetedSpaceGUID: spaceGUID,
			Path:              absPath,
		}

		log.Infoln("searching for app", app.Name)
		found, constructedApp, v2Warnings, err := actor.FindOrReturnPartialApp(app.Name, spaceGUID)
		warnings = append(warnings, v2Warnings...)
		if err != nil {
			log.Errorln("app lookup:", err)
			return nil, warnings, err
		}

		if found {
			var configWarnings v2action.Warnings
			config, configWarnings, err = actor.configureExistingApp(config, app, constructedApp)
			warnings = append(warnings, configWarnings...)
			if err != nil {
				log.Errorln("configuring existing app:", err)
				return nil, warnings, err
			}
		} else {
			log.Debug("using empty app as base")
			config.DesiredApplication = constructedApp
		}

		config.DesiredApplication = actor.overrideApplicationProperties(config.DesiredApplication, app)

		var stackWarnings Warnings
		config.DesiredApplication, stackWarnings, err = actor.overrideStack(config.DesiredApplication, app)
		warnings = append(warnings, stackWarnings...)
		if err != nil {
			return nil, warnings, err
		}

		defaultRoute, routeWarnings, err := actor.GetRouteWithDefaultDomain(app.Name, orgGUID, spaceGUID, config.CurrentRoutes)
		warnings = append(warnings, routeWarnings...)
		if err != nil {
			log.Errorln("getting default route:", err)
			return nil, warnings, err
		}

		// TODO: when working with all of routes, append to current route
		config.DesiredRoutes = []v2action.Route{defaultRoute}

		config, err = actor.configureResources(config, app.DockerImage)
		if err != nil {
			log.Errorln("configuring resources", err)
			return nil, warnings, err
		}

		configs = append(configs, config)
	}

	return configs, warnings, nil
}

func (actor Actor) configureExistingApp(config ApplicationConfig, app manifest.Application, foundApp Application) (ApplicationConfig, v2action.Warnings, error) {
	log.Debugf("found app: %#v", foundApp)
	config.CurrentApplication = foundApp
	config.DesiredApplication = foundApp

	log.Info("looking up application routes")
	routes, warnings, err := actor.V2Actor.GetApplicationRoutes(foundApp.GUID)
	if err != nil {
		log.Errorln("existing routes lookup:", err)
		return config, warnings, err
	}
	config.CurrentRoutes = routes
	return config, warnings, nil
}

func (actor Actor) configureResources(config ApplicationConfig, dockerImagePath string) (ApplicationConfig, error) {
	if dockerImagePath == "" {
		info, err := os.Stat(config.Path)
		if err != nil {
			return config, err
		}

		var resources []v2action.Resource
		if info.IsDir() {
			log.WithField("path_to_resources", config.Path).Info("determine directory resources to zip")
			resources, err = actor.V2Actor.GatherDirectoryResources(config.Path)
		} else {
			config.Archive = true
			log.WithField("path_to_resources", config.Path).Info("determine archive resources to zip")
			resources, err = actor.V2Actor.GatherArchiveResources(config.Path)
		}
		if err != nil {
			return config, err
		}
		config.AllResources = resources
		log.WithField("number_of_files", len(resources)).Debug("completed file scan")
	} else {
		config.DesiredApplication.DockerImage = dockerImagePath
	}

	return config, nil
}

func (Actor) overrideApplicationProperties(application Application, manifest manifest.Application) Application {
	if manifest.Buildpack != "" {
		application.Buildpack = manifest.Buildpack
	}
	if manifest.Command != "" {
		application.Command = manifest.Command
	}
	if manifest.DiskQuota != 0 {
		application.DiskQuota = manifest.DiskQuota
	}
	if manifest.HealthCheckHTTPEndpoint != "" {
		application.HealthCheckHTTPEndpoint = manifest.HealthCheckHTTPEndpoint
	}
	if manifest.HealthCheckTimeout != 0 {
		application.HealthCheckTimeout = manifest.HealthCheckTimeout
	}
	if manifest.HealthCheckType != "" {
		application.HealthCheckType = manifest.HealthCheckType
	}
	if manifest.Instances != 0 {
		application.Instances = manifest.Instances
	}
	if manifest.Memory != 0 {
		application.Memory = manifest.Memory
	}

	return application
}

func (actor Actor) overrideStack(application Application, manifest manifest.Application) (Application, Warnings, error) {
	if manifest.StackName == "" {
		return application, nil, nil
	}
	stack, warnings, err := actor.V2Actor.GetStackByName(manifest.StackName)
	application.SetStack(stack)
	return application, Warnings(warnings), err
}
