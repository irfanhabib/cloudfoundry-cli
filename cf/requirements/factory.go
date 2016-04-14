package requirements

import (
	"github.com/blang/semver"
	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf"
)

//go:generate counterfeiter . Factory

type Factory interface {
	NewApplicationRequirement(name string) ApplicationRequirement
	NewDEAApplicationRequirement(name string) DEAApplicationRequirement
	NewDiegoApplicationRequirement(name string) DiegoApplicationRequirement
	NewServiceInstanceRequirement(name string) ServiceInstanceRequirement
	NewLoginRequirement() Requirement
	NewRoutingAPIRequirement() Requirement
	NewSpaceRequirement(name string) SpaceRequirement
	NewTargetedSpaceRequirement() Requirement
	NewTargetedOrgRequirement() TargetedOrgRequirement
	NewOrganizationRequirement(name string) OrganizationRequirement
	NewDomainRequirement(name string) DomainRequirement
	NewUserRequirement(username string, wantGuid bool) UserRequirement
	NewBuildpackRequirement(buildpack string) BuildpackRequirement
	NewApiEndpointRequirement() Requirement
	NewMinAPIVersionRequirement(commandName string, requiredVersion semver.Version) Requirement
	NewMaxAPIVersionRequirement(commandName string, maximumVersion semver.Version) Requirement
}

type apiRequirementFactory struct {
	config      coreconfig.ReadWriter
	repoLocator api.RepositoryLocator
}

func NewFactory(config coreconfig.ReadWriter, repoLocator api.RepositoryLocator) (factory apiRequirementFactory) {
	return apiRequirementFactory{config, repoLocator}
}

func (f apiRequirementFactory) NewApplicationRequirement(name string) ApplicationRequirement {
	return NewApplicationRequirement(
		name,
		f.repoLocator.GetApplicationRepository(),
	)
}

func (f apiRequirementFactory) NewDEAApplicationRequirement(name string) DEAApplicationRequirement {
	return NewDEAApplicationRequirement(
		name,
		f.repoLocator.GetApplicationRepository(),
	)
}

func (f apiRequirementFactory) NewDiegoApplicationRequirement(name string) DiegoApplicationRequirement {
	return NewDiegoApplicationRequirement(
		name,
		f.repoLocator.GetApplicationRepository(),
	)
}

func (f apiRequirementFactory) NewServiceInstanceRequirement(name string) ServiceInstanceRequirement {
	return NewServiceInstanceRequirement(
		name,
		f.repoLocator.GetServiceRepository(),
	)
}

func (f apiRequirementFactory) NewLoginRequirement() Requirement {
	return NewLoginRequirement(
		f.config,
	)
}

func (f apiRequirementFactory) NewRoutingAPIRequirement() Requirement {
	req := Requirements{
		f.NewMinAPIVersionRequirement("RoutingAPI", cf.TcpRoutingMinimumApiVersion),
		NewRoutingAPIRequirement(
			f.config,
		),
	}

	return req
}

func (f apiRequirementFactory) NewSpaceRequirement(name string) SpaceRequirement {
	return NewSpaceRequirement(
		name,
		f.repoLocator.GetSpaceRepository(),
	)
}

func (f apiRequirementFactory) NewTargetedSpaceRequirement() Requirement {
	return NewTargetedSpaceRequirement(
		f.config,
	)
}

func (f apiRequirementFactory) NewTargetedOrgRequirement() TargetedOrgRequirement {
	return NewTargetedOrgRequirement(
		f.config,
	)
}

func (f apiRequirementFactory) NewOrganizationRequirement(name string) OrganizationRequirement {
	return NewOrganizationRequirement(
		name,
		f.repoLocator.GetOrganizationRepository(),
	)
}

func (f apiRequirementFactory) NewDomainRequirement(name string) DomainRequirement {
	return NewDomainRequirement(
		name,
		f.config,
		f.repoLocator.GetDomainRepository(),
	)
}

func (f apiRequirementFactory) NewUserRequirement(username string, wantGuid bool) UserRequirement {
	return NewUserRequirement(
		username,
		f.repoLocator.GetUserRepository(),
		wantGuid,
	)
}

func (f apiRequirementFactory) NewBuildpackRequirement(buildpack string) BuildpackRequirement {
	return NewBuildpackRequirement(
		buildpack,
		f.repoLocator.GetBuildpackRepository(),
	)
}

func (f apiRequirementFactory) NewApiEndpointRequirement() Requirement {
	return NewApiEndpointRequirement(
		f.config,
	)
}

func (f apiRequirementFactory) NewMinAPIVersionRequirement(commandName string, requiredVersion semver.Version) Requirement {
	r := NewMinAPIVersionRequirement(
		f.config,
		commandName,
		requiredVersion,
	)

	refresher := coreconfig.APIConfigRefresher{
		Endpoint:     f.config.ApiEndpoint(),
		EndpointRepo: f.repoLocator.GetEndpointRepository(),
		Config:       f.config,
	}

	return NewConfigRefreshingRequirement(r, refresher)
}

func (f apiRequirementFactory) NewMaxAPIVersionRequirement(commandName string, maximumVersion semver.Version) Requirement {
	return NewMaxAPIVersionRequirement(
		f.config,
		commandName,
		maximumVersion,
	)
}
