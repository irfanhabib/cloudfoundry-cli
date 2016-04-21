package api_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/net"
	"github.com/cloudfoundry/cli/testhelpers/cloudcontrollergateway"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testnet "github.com/cloudfoundry/cli/testhelpers/net"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func validApiInfoEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v2/info" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, `
{
  "name": "vcap",
  "build": "2222",
  "support": "http://support.cloudfoundry.com",
  "version": 2,
  "description": "Cloud Foundry sponsored by Pivotal",
	"app_ssh_oauth_client": "ssh-client-id",
  "authorization_endpoint": "https://login.example.com",
  "logging_endpoint": "wss://loggregator.foo.example.org:4443",
  "routing_endpoint": "http://api.example.com/routing",
  "api_version": "42.0.0",
	"min_cli_version": "6.5.0",
	"min_recommended_cli_version": "6.7.0"
}`)
}

func apiInfoEndpointWithoutLogURL(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/v2/info") {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmt.Fprintln(w, `
{
  "name": "vcap",
  "build": "2222",
  "support": "http://support.cloudfoundry.com",
  "routing_endpoint": "http://api.example.com/routing",
  "version": 2,
  "description": "Cloud Foundry sponsored by Pivotal",
  "authorization_endpoint": "https://login.example.com",
  "api_version": "42.0.0"
}`)
}

var _ = Describe("Endpoints Repository", func() {
	var (
		coreConfig   coreconfig.ReadWriter
		gateway      net.Gateway
		testServer   *httptest.Server
		repo         RemoteInfoRepository
		testServerFn func(w http.ResponseWriter, r *http.Request)
	)

	BeforeEach(func() {
		coreConfig = testconfig.NewRepository()
		testServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testServerFn(w, r)
		}))
		gateway = cloudcontrollergateway.NewTestCloudControllerGateway(coreConfig)
		gateway.SetTrustedCerts(testServer.TLS.Certificates)
		repo = NewEndpointRepository(gateway)
	})

	AfterEach(func() {
		testServer.Close()
	})

	Describe("updating the endpoints", func() {
		Context("when the API request is successful", func() {
			var (
				org   models.OrganizationFields
				space models.SpaceFields
			)
			BeforeEach(func() {
				org.Name = "my-org"
				org.GUID = "my-org-guid"

				space.Name = "my-space"
				space.GUID = "my-space-guid"

				coreConfig.SetOrganizationFields(org)
				coreConfig.SetSpaceFields(space)
				testServerFn = validApiInfoEndpoint
			})

			It("returns the configuration info from /info", func() {
				config, endpoint, err := repo.GetCCInfo(testServer.URL)

				Expect(err).NotTo(HaveOccurred())
				Expect(config.AuthorizationEndpoint).To(Equal("https://login.example.com"))
				Expect(config.LoggregatorEndpoint).To(Equal("wss://loggregator.foo.example.org:4443"))
				Expect(endpoint).To(Equal(testServer.URL))
				Expect(config.SSHOAuthClient).To(Equal("ssh-client-id"))
				Expect(config.ApiVersion).To(Equal("42.0.0"))
				Expect(config.MinCliVersion).To(Equal("6.5.0"))
				Expect(config.MinRecommendedCliVersion).To(Equal("6.7.0"))
				Expect(config.RoutingApiEndpoint).To(Equal("http://api.example.com/routing"))
			})
		})

		Context("when the API request fails", func() {
			BeforeEach(func() {
				coreConfig.SetApiEndpoint("example.com")
			})

			It("returns a failure response when the server has a bad certificate", func() {
				testServer.TLS.Certificates = []tls.Certificate{testnet.MakeExpiredTLSCert()}

				_, _, apiErr := repo.GetCCInfo(testServer.URL)
				Expect(apiErr).NotTo(BeNil())
			})

			It("returns a failure response when the API request fails", func() {
				testServerFn = func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}

				_, _, apiErr := repo.GetCCInfo(testServer.URL)

				Expect(apiErr).NotTo(BeNil())
			})

			It("returns a failure response when the API returns invalid JSON", func() {
				testServerFn = func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintln(w, `Foo`)
				}

				_, _, apiErr := repo.GetCCInfo(testServer.URL)

				Expect(apiErr).NotTo(BeNil())
			})
		})

		Describe("when the specified API url doesn't have a scheme", func() {
			It("uses https if possible", func() {
				testServerFn = validApiInfoEndpoint

				schemelessURL := strings.Replace(testServer.URL, "https://", "", 1)
				config, endpoint, apiErr := repo.GetCCInfo(schemelessURL)
				Expect(endpoint).To(Equal(testServer.URL))

				Expect(apiErr).NotTo(HaveOccurred())

				Expect(config.AuthorizationEndpoint).To(Equal("https://login.example.com"))
				Expect(config.ApiVersion).To(Equal("42.0.0"))
			})

			It("uses http when the server doesn't respond over https", func() {
				testServer.Close()
				testServer = httptest.NewServer(http.HandlerFunc(validApiInfoEndpoint))
				schemelessURL := strings.Replace(testServer.URL, "http://", "", 1)

				config, endpoint, apiErr := repo.GetCCInfo(schemelessURL)

				Expect(endpoint).To(Equal(testServer.URL))
				Expect(apiErr).NotTo(HaveOccurred())

				Expect(config.AuthorizationEndpoint).To(Equal("https://login.example.com"))
				Expect(config.ApiVersion).To(Equal("42.0.0"))
			})
		})
	})
})
