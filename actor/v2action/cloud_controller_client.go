package v2action

import "code.cloudfoundry.org/cli/api/cloudcontroller/ccv2"

//go:generate counterfeiter . CloudControllerClient

// CloudControllerClient is a Cloud Controller V2 client.
type CloudControllerClient interface {
	AssociateSpaceWithSecurityGroup(securityGroupGUID string, spaceGUID string) (ccv2.Warnings, error)
	CreateApplication(app ccv2.Application) (ccv2.Application, ccv2.Warnings, error)
	CreateUser(uaaUserID string) (ccv2.User, ccv2.Warnings, error)
	DeleteOrganization(orgGUID string) (ccv2.Job, ccv2.Warnings, error)
	DeleteRoute(routeGUID string) (ccv2.Warnings, error)
	DeleteServiceBinding(serviceBindingGUID string) (ccv2.Warnings, error)
	GetApplication(guid string) (ccv2.Application, ccv2.Warnings, error)
	GetApplicationInstancesByApplication(guid string) (map[int]ccv2.ApplicationInstance, ccv2.Warnings, error)
	GetApplicationInstanceStatusesByApplication(guid string) (map[int]ccv2.ApplicationInstanceStatus, ccv2.Warnings, error)
	GetApplicationRoutes(appGUID string, queries []ccv2.Query) ([]ccv2.Route, ccv2.Warnings, error)
	GetApplications(queries []ccv2.Query) ([]ccv2.Application, ccv2.Warnings, error)
	GetJob(jobGUID string) (ccv2.Job, ccv2.Warnings, error)
	GetOrganization(guid string) (ccv2.Organization, ccv2.Warnings, error)
	GetOrganizationPrivateDomains(orgGUID string, queries []ccv2.Query) ([]ccv2.Domain, ccv2.Warnings, error)
	GetOrganizationQuota(guid string) (ccv2.OrganizationQuota, ccv2.Warnings, error)
	GetOrganizations(queries []ccv2.Query) ([]ccv2.Organization, ccv2.Warnings, error)
	GetPrivateDomain(domainGUID string) (ccv2.Domain, ccv2.Warnings, error)
	GetRouteApplications(routeGUID string, queries []ccv2.Query) ([]ccv2.Application, ccv2.Warnings, error)
	GetRoutes(queries []ccv2.Query) ([]ccv2.Route, ccv2.Warnings, error)
	GetSecurityGroups(queries []ccv2.Query) ([]ccv2.SecurityGroup, ccv2.Warnings, error)
	GetServiceBindings(queries []ccv2.Query) ([]ccv2.ServiceBinding, ccv2.Warnings, error)
	GetServiceInstances(queries []ccv2.Query) ([]ccv2.ServiceInstance, ccv2.Warnings, error)
	GetSharedDomain(domainGUID string) (ccv2.Domain, ccv2.Warnings, error)
	GetSharedDomains() ([]ccv2.Domain, ccv2.Warnings, error)
	GetSpaceQuota(guid string) (ccv2.SpaceQuota, ccv2.Warnings, error)
	GetSpaceRoutes(spaceGUID string, queries []ccv2.Query) ([]ccv2.Route, ccv2.Warnings, error)
	GetSpaceRunningSecurityGroupsBySpace(spaceGUID string) ([]ccv2.SecurityGroup, ccv2.Warnings, error)
	GetSpaces(queries []ccv2.Query) ([]ccv2.Space, ccv2.Warnings, error)
	GetSpaceServiceInstances(spaceGUID string, includeUserProvidedServices bool, queries []ccv2.Query) ([]ccv2.ServiceInstance, ccv2.Warnings, error)
	GetSpaceStagingSecurityGroupsBySpace(spaceGUID string) ([]ccv2.SecurityGroup, ccv2.Warnings, error)
	GetStack(guid string) (ccv2.Stack, ccv2.Warnings, error)
	PollJob(job ccv2.Job) (ccv2.Warnings, error)
	TargetCF(settings ccv2.TargetSettings) (ccv2.Warnings, error)
	UpdateApplication(app ccv2.Application) (ccv2.Application, ccv2.Warnings, error)

	API() string
	APIVersion() string
	AuthorizationEndpoint() string
	DopplerEndpoint() string
	MinCLIVersion() string
	RoutingEndpoint() string
	TokenEndpoint() string
}
