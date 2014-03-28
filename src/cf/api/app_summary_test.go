package api_test

import (
	. "cf/api"
	"cf/net"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/http/httptest"
	testapi "testhelpers/api"
	testconfig "testhelpers/configuration"
	testnet "testhelpers/net"
)

var _ = Describe("AppSummaryRepository", func() {
	It("TestGetAppSummariesInCurrentSpace", func() {
		getAppSummariesRequest := testapi.NewCloudControllerTestRequest(testnet.TestRequest{
			Method:   "GET",
			Path:     "/v2/spaces/my-space-guid/summary",
			Response: testnet.TestResponse{Status: http.StatusOK, Body: getAppSummariesResponseBody},
		})

		ts, handler, repo := createAppSummaryRepo([]testnet.TestRequest{getAppSummariesRequest})
		defer ts.Close()

		apps, apiErr := repo.GetSummariesInCurrentSpace()
		Expect(handler).To(testnet.HaveAllRequestsCalled())

		Expect(apiErr).NotTo(HaveOccurred())
		Expect(2).To(Equal(len(apps)))

		app1 := apps[0]
		Expect(app1.Name).To(Equal("app1"))
		Expect(app1.Guid).To(Equal("app-1-guid"))
		Expect(len(app1.Routes)).To(Equal(1))
		Expect(app1.Routes[0].URL()).To(Equal("app1.cfapps.io"))

		Expect(app1.State).To(Equal("started"))
		Expect(app1.InstanceCount).To(Equal(1))
		Expect(app1.RunningInstances).To(Equal(1))
		Expect(app1.Memory).To(Equal(uint64(128)))

		app2 := apps[1]
		Expect(app2.Name).To(Equal("app2"))
		Expect(app2.Guid).To(Equal("app-2-guid"))
		Expect(len(app2.Routes)).To(Equal(2))
		Expect(app2.Routes[0].URL()).To(Equal("app2.cfapps.io"))
		Expect(app2.Routes[1].URL()).To(Equal("foo.cfapps.io"))

		Expect(app2.State).To(Equal("started"))
		Expect(app2.InstanceCount).To(Equal(3))
		Expect(app2.RunningInstances).To(Equal(1))
		Expect(app2.Memory).To(Equal(uint64(512)))
	})
})

var getAppSummariesResponseBody = `
{
  "apps":[
    {
      "guid":"app-1-guid",
      "routes":[
        {
          "guid":"route-1-guid",
          "host":"app1",
          "domain":{
            "guid":"domain-1-guid",
            "name":"cfapps.io"
          }
        }
      ],
      "running_instances":1,
      "name":"app1",
      "memory":128,
      "instances":1,
      "state":"STARTED",
      "service_names":[
      	"my-service-instance"
      ]
    },{
      "guid":"app-2-guid",
      "routes":[
        {
          "guid":"route-2-guid",
          "host":"app2",
          "domain":{
            "guid":"domain-1-guid",
            "name":"cfapps.io"
          }
        },
        {
          "guid":"route-2-guid",
          "host":"foo",
          "domain":{
            "guid":"domain-1-guid",
            "name":"cfapps.io"
          }
        }
      ],
      "running_instances":1,
      "name":"app2",
      "memory":512,
      "instances":3,
      "state":"STARTED",
      "service_names":[
      	"my-service-instance"
      ]
    }
  ]
}`

func createAppSummaryRepo(requests []testnet.TestRequest) (ts *httptest.Server, handler *testnet.TestHandler, repo AppSummaryRepository) {
	ts, handler = testnet.NewServer(requests)
	configRepo := testconfig.NewRepositoryWithDefaults()
	configRepo.SetApiEndpoint(ts.URL)
	gateway := net.NewCloudControllerGateway(configRepo)
	repo = NewCloudControllerAppSummaryRepository(configRepo, gateway)
	return
}
