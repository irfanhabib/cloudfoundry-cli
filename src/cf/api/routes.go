package api

import (
	"cf/api/resources"
	"cf/configuration"
	"cf/errors"
	"cf/models"
	"cf/net"
	"fmt"
	"net/url"
	"strings"
)

type RouteRepository interface {
	ListRoutes(cb func(models.Route) bool) (apiErr error)
	FindByHostAndDomain(host, domain string) (route models.Route, apiErr error)
	Create(host, domainGuid string) (createdRoute models.Route, apiErr error)
	CreateInSpace(host, domainGuid, spaceGuid string) (createdRoute models.Route, apiErr error)
	Bind(routeGuid, appGuid string) (apiErr error)
	Unbind(routeGuid, appGuid string) (apiErr error)
	Delete(routeGuid string) (apiErr error)
}

type CloudControllerRouteRepository struct {
	config     configuration.Reader
	gateway    net.Gateway
	domainRepo DomainRepository
}

func NewCloudControllerRouteRepository(config configuration.Reader, gateway net.Gateway, domainRepo DomainRepository) (repo CloudControllerRouteRepository) {
	repo.config = config
	repo.gateway = gateway
	repo.domainRepo = domainRepo
	return
}

func (repo CloudControllerRouteRepository) ListRoutes(cb func(models.Route) bool) (apiErr error) {
	return repo.gateway.ListPaginatedResources(
		repo.config.ApiEndpoint(),
		repo.config.AccessToken(),
		fmt.Sprintf("/v2/spaces/%s/routes?inline-relations-depth=1", repo.config.SpaceFields().Guid),
		resources.RouteResource{},
		func(resource interface{}) bool {
			return cb(resource.(resources.RouteResource).ToModel())
		})
}

func (repo CloudControllerRouteRepository) FindByHostAndDomain(host, domainName string) (route models.Route, apiErr error) {
	domain, apiErr := repo.domainRepo.FindByName(domainName)
	if apiErr != nil {
		return
	}

	found := false
	apiErr = repo.gateway.ListPaginatedResources(
		repo.config.ApiEndpoint(),
		repo.config.AccessToken(),
		fmt.Sprintf("/v2/routes?inline-relations-depth=1&q=%s", url.QueryEscape("host:"+host+";domain_guid:"+domain.Guid)),
		resources.RouteResource{},
		func(resource interface{}) bool {
			route = resource.(resources.RouteResource).ToModel()
			found = true
			return false
		})

	if apiErr == nil && !found {
		apiErr = errors.NewModelNotFoundError("Route", host)
	}

	return
}

func (repo CloudControllerRouteRepository) Create(host, domainGuid string) (createdRoute models.Route, apiErr error) {
	return repo.CreateInSpace(host, domainGuid, repo.config.SpaceFields().Guid)
}

func (repo CloudControllerRouteRepository) CreateInSpace(host, domainGuid, spaceGuid string) (createdRoute models.Route, apiErr error) {
	path := fmt.Sprintf("%s/v2/routes?inline-relations-depth=1", repo.config.ApiEndpoint())
	data := fmt.Sprintf(`{"host":"%s","domain_guid":"%s","space_guid":"%s"}`, host, domainGuid, spaceGuid)

	resource := new(resources.RouteResource)
	apiErr = repo.gateway.CreateResourceForResponse(path, repo.config.AccessToken(), strings.NewReader(data), resource)
	if apiErr != nil {
		return
	}

	createdRoute = resource.ToModel()
	return
}

func (repo CloudControllerRouteRepository) Bind(routeGuid, appGuid string) (apiErr error) {
	path := fmt.Sprintf("%s/v2/apps/%s/routes/%s", repo.config.ApiEndpoint(), appGuid, routeGuid)
	return repo.gateway.UpdateResource(path, repo.config.AccessToken(), nil)
}

func (repo CloudControllerRouteRepository) Unbind(routeGuid, appGuid string) (apiErr error) {
	path := fmt.Sprintf("%s/v2/apps/%s/routes/%s", repo.config.ApiEndpoint(), appGuid, routeGuid)
	return repo.gateway.DeleteResource(path, repo.config.AccessToken())
}

func (repo CloudControllerRouteRepository) Delete(routeGuid string) (apiErr error) {
	path := fmt.Sprintf("%s/v2/routes/%s", repo.config.ApiEndpoint(), routeGuid)
	return repo.gateway.DeleteResource(path, repo.config.AccessToken())
}
