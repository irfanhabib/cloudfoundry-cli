package v2action

import (
	"code.cloudfoundry.org/cli/actor/pushaction/manifest"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv2"
)

func (actor Actor) CreateApplicationManifestByNameAndSpace(appName string, spaceGUID string, pathToFile string) (Warnings, error) {

	var allWarnings Warnings
	applicationSummary, appSummaryWarnings, err := actor.GetApplicationSummaryByNameAndSpace(appName, spaceGUID)
	allWarnings = append(allWarnings, appSummaryWarnings...)
	if err != nil {
		return allWarnings, err
	}

	serviceInstances, serviceWarnings, err := actor.GetServiceInstancesByApplication(applicationSummary.GUID)
	allWarnings = append(allWarnings, serviceWarnings...)
	if err != nil {
		return allWarnings, err
	}

	var routes []string
	for _, route := range applicationSummary.Routes {
		routes = append(routes, route.String())
	}

	var services []string
	for _, serviceInstace := range serviceInstances {
		services = append(services, serviceInstace.Name)
	}

	manifestApp := manifest.Application{
		Buildpack:            applicationSummary.Buildpack,
		Command:              applicationSummary.Command,
		DiskQuota:            applicationSummary.DiskQuota,
		EnvironmentVariables: applicationSummary.EnvironmentVariables,
		HealthCheckTimeout:   applicationSummary.HealthCheckTimeout,
		Instances:            applicationSummary.Instances,
		Memory:               applicationSummary.Memory,
		Name:                 applicationSummary.Name,
		Routes:               routes,
		Services:             services,
		StackName:            applicationSummary.Stack.Name,
	}

	if applicationSummary.HealthCheckType != ccv2.ApplicationHealthCheckPort {
		manifestApp.HealthCheckType = string(applicationSummary.HealthCheckType)

		if applicationSummary.HealthCheckType == ccv2.ApplicationHealthCheckHTTP &&
			applicationSummary.HealthCheckHTTPEndpoint != "/" {
			manifestApp.HealthCheckHTTPEndpoint = applicationSummary.HealthCheckHTTPEndpoint
		}
	}

	err = manifest.WriteApplicationManifest(manifestApp, pathToFile)
	return allWarnings, err
}
