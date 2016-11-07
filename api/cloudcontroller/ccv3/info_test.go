package ccv3_test

import (
	"fmt"
	"net/http"

	. "code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/ghttp"
)

var _ = Describe("Info", func() {
	var (
		client          *Client
		rootRespondWith http.HandlerFunc
		v3RespondWith   http.HandlerFunc
	)

	JustBeforeEach(func() {
		client = NewTestClient()

		server.AppendHandlers(
			CombineHandlers(
				VerifyRequest(http.MethodGet, "/"),
				rootRespondWith,
			),
			CombineHandlers(
				VerifyRequest(http.MethodGet, "/v3"),
				v3RespondWith,
			))
	})

	Describe("when all requests are successful", func() {
		BeforeEach(func() {
			rootResponse := fmt.Sprintf(`{
				"links": {
					"self": {
						"href": "%s"
					},
					"cloud_controller_v2": {
						"href": "%s/v2",
						"meta": {
							"version": "2.64.0"
						}
					},
					"cloud_controller_v3": {
						"href": "%s/v3",
						"meta": {
							"version": "3.0.0-alpha.5"
						}
					}
				}
			}
			`, server.URL(), server.URL(), server.URL())

			rootRespondWith = RespondWith(
				http.StatusOK,
				rootResponse,
				http.Header{"X-Cf-Warnings": {"warning 1"}})

			v3Response := fmt.Sprintf(`{
				"links": {
					"self": {
						"href": "%s/v3"
					},
					"tasks": {
						"href": "%s/v3/tasks"
					},
					"uaa": {
						"href": "https://uaa.bosh-lite.com"
					}
				}
			}
			`, server.URL(), server.URL())

			v3RespondWith = RespondWith(
				http.StatusOK,
				v3Response,
				http.Header{"X-Cf-Warnings": {"warning 2"}})
		})

		It("returns back the CC Information", func() {
			info, _, err := client.Info()
			Expect(err).NotTo(HaveOccurred())
			Expect(info.UAA()).To(Equal("https://uaa.bosh-lite.com"))
		})

		It("returns all warnings", func() {
			_, warnings, err := client.Info()
			Expect(err).NotTo(HaveOccurred())
			Expect(warnings).To(ConsistOf("warning 1", "warning 2"))
		})
	})

	Context("when the uaa endpoint does not exist", func() {
		BeforeEach(func() {
			response := `{
				 "links": {
						"self": {
							 "href": "https://api.bosh-lite.com/v3"
						},
						"tasks": {
							 "href": "https://api.bosh-lite.com/v3/tasks"
						}
				 }
			}`

			v3RespondWith = RespondWith(
				http.StatusOK,
				response,
				http.Header{"X-Cf-Warnings": {"this is a warning"}})
		})

		It("returns an empty endpoint", func() {
			info, _, err := client.Info()
			Expect(err).NotTo(HaveOccurred())

			Expect(info.UAA()).To(BeEmpty())
		})
	})

	Context("when the cloud controller encounters an error", func() {
		Context("when the error occurs making a request to '/'", func() {
			BeforeEach(func() {
				rootRespondWith = RespondWith(
					http.StatusNotFound,
					`{"errors": [{}]}`,
					http.Header{"X-Cf-Warnings": {"this is a warning"}})
			})

			It("returns the same error", func() {
				_, warnings, err := client.Info()
				Expect(err).To(MatchError(ResourceNotFoundError{}))
				Expect(warnings).To(ConsistOf("this is a warning"))
			})
		})

		Context("when the error occurs making a request to '/v3'", func() {
			BeforeEach(func() {
				v3RespondWith = RespondWith(
					http.StatusNotFound,
					`{"errors": [{}]}`,
					http.Header{"X-Cf-Warnings": {"this is a warning"}})
			})

			It("returns the same error", func() {
				_, warnings, err := client.Info()
				Expect(err).To(MatchError(ResourceNotFoundError{}))
				Expect(warnings).To(ConsistOf("this is a warning"))
			})
		})
	})
})
