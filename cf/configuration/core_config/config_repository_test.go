package core_config_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/testhelpers/maker"

	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Configuration Repository", func() {
	var config core_config.Repository

	BeforeEach(func() {
		config = core_config.NewRepositoryFromPersistor(testconfig.NewFakePersistor(), func(err error) { panic(err) })
	})

	It("is safe for concurrent reading and writing", func() {
		swapValLoop := func(config core_config.Repository) {
			for {
				val := config.ApiEndpoint()

				switch val {
				case "foo":
					config.SetApiEndpoint("bar")
				case "bar":
					config.SetApiEndpoint("foo")
				default:
					panic(fmt.Sprintf("WAT: %s", val))
				}
			}
		}

		config.SetApiEndpoint("foo")

		go swapValLoop(config)
		go swapValLoop(config)
		go swapValLoop(config)
		go swapValLoop(config)

		time.Sleep(10 * time.Millisecond)
	})

	It("has acccessor methods for all config fields", func() {
		config.SetApiEndpoint("http://api.the-endpoint")
		Expect(config.ApiEndpoint()).To(Equal("http://api.the-endpoint"))

		config.SetApiVersion("3")
		Expect(config.ApiVersion()).To(Equal("3"))

		config.SetAuthenticationEndpoint("http://auth.the-endpoint")
		Expect(config.AuthenticationEndpoint()).To(Equal("http://auth.the-endpoint"))

		config.SetLoggregatorEndpoint("http://loggregator.the-endpoint")
		Expect(config.LoggregatorEndpoint()).To(Equal("http://loggregator.the-endpoint"))

		config.SetDopplerEndpoint("http://doppler.the-endpoint")
		Expect(config.DopplerEndpoint()).To(Equal("http://doppler.the-endpoint"))

		config.SetUaaEndpoint("http://uaa.the-endpoint")
		Expect(config.UaaEndpoint()).To(Equal("http://uaa.the-endpoint"))

		config.SetAccessToken("the-token")
		Expect(config.AccessToken()).To(Equal("the-token"))

		config.SetSSHOAuthClient("oauth-client-id")
		Expect(config.SSHOAuthClient()).To(Equal("oauth-client-id"))

		config.SetRefreshToken("the-token")
		Expect(config.RefreshToken()).To(Equal("the-token"))

		organization := maker.NewOrgFields(maker.Overrides{"name": "the-org"})
		config.SetOrganizationFields(organization)
		Expect(config.OrganizationFields()).To(Equal(organization))

		space := maker.NewSpaceFields(maker.Overrides{"name": "the-space"})
		config.SetSpaceFields(space)
		Expect(config.SpaceFields()).To(Equal(space))

		config.SetSSLDisabled(false)
		Expect(config.IsSSLDisabled()).To(BeFalse())

		config.SetLocale("en_US")
		Expect(config.Locale()).To(Equal("en_US"))

		config.SetPluginRepo(models.PluginRepo{Name: "repo", Url: "nowhere.com"})
		Expect(config.PluginRepos()[0].Name).To(Equal("repo"))
		Expect(config.PluginRepos()[0].Url).To(Equal("nowhere.com"))

		Expect(config.IsMinApiVersion("3.1")).To(Equal(false))

		config.SetMinCliVersion("6.5.0")
		Expect(config.IsMinCliVersion("5.0.0")).To(Equal(false))
		Expect(config.IsMinCliVersion("6.10.0")).To(Equal(true))
		Expect(config.IsMinCliVersion("6.5.0")).To(Equal(true))
		Expect(config.IsMinCliVersion("6.5.0.1")).To(Equal(true))
		Expect(config.MinCliVersion()).To(Equal("6.5.0"))

		config.SetMinRecommendedCliVersion("6.9.0")
		Expect(config.MinRecommendedCliVersion()).To(Equal("6.9.0"))
	})

	Describe("HasAPIEndpoint", func() {
		Context("when both endpoint and version are set", func() {
			BeforeEach(func() {
				config.SetApiEndpoint("http://example.org")
				config.SetApiVersion("42.1.2.3")
			})

			It("returns true", func() {
				Expect(config.HasAPIEndpoint()).To(BeTrue())
			})
		})

		Context("when endpoint is not set", func() {
			BeforeEach(func() {
				config.SetApiVersion("42.1.2.3")
			})

			It("returns false", func() {
				Expect(config.HasAPIEndpoint()).To(BeFalse())
			})
		})

		Context("when version is not set", func() {
			BeforeEach(func() {
				config.SetApiEndpoint("http://example.org")
			})

			It("returns false", func() {
				Expect(config.HasAPIEndpoint()).To(BeFalse())
			})
		})
	})

	Describe("UserGuid", func() {
		Context("with a valid access token", func() {
			BeforeEach(func() {
				config.SetAccessToken("bearer eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJjNDE4OTllNS1kZTE1LTQ5NGQtYWFiNC04ZmNlYzUxN2UwMDUiLCJzdWIiOiI3NzJkZGEzZi02NjlmLTQyNzYtYjJiZC05MDQ4NmFiZTFmNmYiLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiXSwiY2xpZW50X2lkIjoiY2YiLCJjaWQiOiJjZiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiI3NzJkZGEzZi02NjlmLTQyNzYtYjJiZC05MDQ4NmFiZTFmNmYiLCJ1c2VyX25hbWUiOiJ1c2VyMUBleGFtcGxlLmNvbSIsImVtYWlsIjoidXNlcjFAZXhhbXBsZS5jb20iLCJpYXQiOjEzNzcwMjgzNTYsImV4cCI6MTM3NzAzNTU1NiwiaXNzIjoiaHR0cHM6Ly91YWEuYXJib3JnbGVuLmNmLWFwcC5jb20vb2F1dGgvdG9rZW4iLCJhdWQiOlsib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlciIsInBhc3N3b3JkIl19.kjFJHi0Qir9kfqi2eyhHy6kdewhicAFu8hrPR1a5AxFvxGB45slKEjuP0_72cM_vEYICgZn3PcUUkHU9wghJO9wjZ6kiIKK1h5f2K9g-Iprv9BbTOWUODu1HoLIvg2TtGsINxcRYy_8LW1RtvQc1b4dBPoopaEH4no-BIzp0E5E")
			})

			It("returns the guid", func() {
				Expect(config.UserGuid()).To(Equal("772dda3f-669f-4276-b2bd-90486abe1f6f"))
			})
		})

		Context("with an invalid access token", func() {
			BeforeEach(func() {
				config.SetAccessToken("bearer eyJhbGciOiJSUzI1NiJ9")
			})

			It("returns an empty string", func() {
				Expect(config.UserGuid()).To(BeEmpty())
			})
		})
	})

	Describe("UserEmail", func() {
		Context("with a valid access token", func() {
			BeforeEach(func() {
				config.SetAccessToken("bearer eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJjNDE4OTllNS1kZTE1LTQ5NGQtYWFiNC04ZmNlYzUxN2UwMDUiLCJzdWIiOiI3NzJkZGEzZi02NjlmLTQyNzYtYjJiZC05MDQ4NmFiZTFmNmYiLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLnJlYWQiLCJjbG91ZF9jb250cm9sbGVyLndyaXRlIiwib3BlbmlkIiwicGFzc3dvcmQud3JpdGUiXSwiY2xpZW50X2lkIjoiY2YiLCJjaWQiOiJjZiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiI3NzJkZGEzZi02NjlmLTQyNzYtYjJiZC05MDQ4NmFiZTFmNmYiLCJ1c2VyX25hbWUiOiJ1c2VyMUBleGFtcGxlLmNvbSIsImVtYWlsIjoidXNlcjFAZXhhbXBsZS5jb20iLCJpYXQiOjEzNzcwMjgzNTYsImV4cCI6MTM3NzAzNTU1NiwiaXNzIjoiaHR0cHM6Ly91YWEuYXJib3JnbGVuLmNmLWFwcC5jb20vb2F1dGgvdG9rZW4iLCJhdWQiOlsib3BlbmlkIiwiY2xvdWRfY29udHJvbGxlciIsInBhc3N3b3JkIl19.kjFJHi0Qir9kfqi2eyhHy6kdewhicAFu8hrPR1a5AxFvxGB45slKEjuP0_72cM_vEYICgZn3PcUUkHU9wghJO9wjZ6kiIKK1h5f2K9g-Iprv9BbTOWUODu1HoLIvg2TtGsINxcRYy_8LW1RtvQc1b4dBPoopaEH4no-BIzp0E5E")
			})

			It("returns the email", func() {
				Expect(config.UserEmail()).To(Equal("user1@example.com"))
			})
		})

		Context("with an invalid access token", func() {
			BeforeEach(func() {
				config.SetAccessToken("bearer eyJhbGciOiJSUzI1NiJ9")
			})

			It("returns an empty string", func() {
				Expect(config.UserEmail()).To(BeEmpty())
			})
		})
	})

	Describe("NewRepositoryFromFilepath", func() {
		var configPath string

		It("returns nil repository if no error handler provided", func() {
			config = core_config.NewRepositoryFromFilepath(configPath, nil)
			Expect(config).To(BeNil())
		})

		Context("when the configuration file doesn't exist", func() {
			var tmpDir string

			BeforeEach(func() {
				tmpDir, err := ioutil.TempDir("", "test-config")
				if err != nil {
					Fail("Couldn't create tmp file")
				}

				configPath = filepath.Join(tmpDir, ".cf", "config.json")
			})

			AfterEach(func() {
				if tmpDir != "" {
					os.RemoveAll(tmpDir)
				}
			})

			It("has sane defaults when there is no config to read", func() {
				config = core_config.NewRepositoryFromFilepath(configPath, func(err error) {
					panic(err)
				})

				Expect(config.ApiEndpoint()).To(Equal(""))
				Expect(config.ApiVersion()).To(Equal(""))
				Expect(config.AuthenticationEndpoint()).To(Equal(""))
				Expect(config.AccessToken()).To(Equal(""))
			})
		})

		Context("when the configuration version is older than the current version", func() {
			BeforeEach(func() {
				cwd, err := os.Getwd()
				Expect(err).NotTo(HaveOccurred())
				configPath = filepath.Join(cwd, "..", "..", "..", "fixtures", "config", "outdated-config", ".cf", "config.json")
			})

			It("returns a new empty config", func() {
				config = core_config.NewRepositoryFromFilepath(configPath, func(err error) {
					panic(err)
				})

				Expect(config.ApiEndpoint()).To(Equal(""))
			})
		})
	})
})
