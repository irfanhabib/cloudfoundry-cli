package appfiles

import (
	"fmt"

	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/net"
)

//go:generate counterfeiter . AppFilesRepository

type AppFilesRepository interface {
	ListFiles(appGUID string, instance int, path string) (files string, apiErr error)
}

type CloudControllerAppFilesRepository struct {
	config  coreconfig.Reader
	gateway net.Gateway
}

func NewCloudControllerAppFilesRepository(config coreconfig.Reader, gateway net.Gateway) (repo CloudControllerAppFilesRepository) {
	repo.config = config
	repo.gateway = gateway
	return
}

func (repo CloudControllerAppFilesRepository) ListFiles(appGUID string, instance int, path string) (files string, apiErr error) {
	url := fmt.Sprintf("%s/v2/apps/%s/instances/%d/files/%s", repo.config.APIEndpoint(), appGUID, instance, path)
	request, apiErr := repo.gateway.NewRequest("GET", url, repo.config.AccessToken(), nil)
	if apiErr != nil {
		return
	}

	files, _, apiErr = repo.gateway.PerformRequestForTextResponse(request)
	return
}
