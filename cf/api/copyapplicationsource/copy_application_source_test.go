package copyapplicationsource_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/cloudfoundry/cli/cf/api/apifakes"
	. "github.com/cloudfoundry/cli/cf/api/copyapplicationsource"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/testhelpers/cloudcontrollergateway"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testnet "github.com/cloudfoundry/cli/testhelpers/net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CopyApplicationSource", func() {
	var (
		repo       CopyApplicationSourceRepository
		testServer *httptest.Server
		configRepo coreconfig.ReadWriter
	)

	setupTestServer := func(reqs ...testnet.TestRequest) {
		testServer, _ = testnet.NewServer(reqs)
		configRepo.SetApiEndpoint(testServer.URL)
	}

	BeforeEach(func() {
		configRepo = testconfig.NewRepositoryWithDefaults()
		gateway := cloudcontrollergateway.NewTestCloudControllerGateway(configRepo)
		repo = NewCloudControllerCopyApplicationSourceRepository(configRepo, gateway)
	})

	AfterEach(func() {
		testServer.Close()
	})

	Describe(".CopyApplication", func() {
		BeforeEach(func() {
			setupTestServer(apifakes.NewCloudControllerTestRequest(testnet.TestRequest{
				Method: "POST",
				Path:   "/v2/apps/target-app-guid/copy_bits",
				Matcher: testnet.RequestBodyMatcher(`{
					"source_app_guid": "source-app-guid"
				}`),
				Response: testnet.TestResponse{
					Status: http.StatusCreated,
				},
			}))
		})

		It("should return a CopyApplicationModel", func() {
			err := repo.CopyApplication("source-app-guid", "target-app-guid")
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
