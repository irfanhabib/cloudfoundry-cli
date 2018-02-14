package configv3_test

import (
	"time"

	. "code.cloudfoundry.org/cli/util/configv3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("JSONConfig", func() {
	var homeDir string

	BeforeEach(func() {
		homeDir = setup()
	})

	AfterEach(func() {
		teardown(homeDir)
	})

	Describe("AccessToken", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "AccessToken":"some-token" }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns fields directly from config", func() {
			Expect(config.AccessToken()).To(Equal("some-token"))
		})
	})

	Describe("APIVersion", func() {
		It("returns the api version", func() {
			config := Config{
				ConfigFile: JSONConfig{
					APIVersion: "2.59.0",
				},
			}

			Expect(config.APIVersion()).To(Equal("2.59.0"))
		})
	})

	Describe("HasTargetedOrganization", func() {
		Context("when an organization is targeted", func() {
			It("returns true", func() {
				config := Config{}
				config.SetOrganizationInformation("guid-value-1", "my-org-name")
				Expect(config.HasTargetedOrganization()).To(BeTrue())
			})
		})

		Context("when an organization is not targeted", func() {
			It("returns false", func() {
				config := Config{}
				Expect(config.HasTargetedOrganization()).To(BeFalse())
			})
		})
	})

	Describe("HasTargetedSpace", func() {
		Context("when an space is targeted", func() {
			It("returns true", func() {
				config := Config{}
				config.SetSpaceInformation("guid-value-1", "my-org-name", true)
				Expect(config.HasTargetedSpace()).To(BeTrue())
			})
		})

		Context("when an space is not targeted", func() {
			It("returns false", func() {
				config := Config{}
				Expect(config.HasTargetedSpace()).To(BeFalse())
			})
		})
	})

	Describe("MinCLIVersion", func() {
		It("returns the minimum CLI version the CC requires", func() {
			config := Config{
				ConfigFile: JSONConfig{
					MinCLIVersion: "1.0.0",
				},
			}

			Expect(config.MinCLIVersion()).To(Equal("1.0.0"))
		})
	})

	Describe("OverallPollingTimeout", func() {
		var config *Config

		Context("when AsyncTimeout is set in config", func() {
			BeforeEach(func() {
				rawConfig := `{ "AsyncTimeout":5 }`
				setConfig(homeDir, rawConfig)

				var err error
				config, err = LoadConfig()
				Expect(err).ToNot(HaveOccurred())
				Expect(config).ToNot(BeNil())
			})

			It("returns the timeout in duration form", func() {
				Expect(config.OverallPollingTimeout()).To(Equal(5 * time.Minute))
			})
		})
	})

	Describe("RefreshToken", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "RefreshToken":"some-token" }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns fields directly from config", func() {
			Expect(config.RefreshToken()).To(Equal("some-token"))
		})
	})

	Describe("SetAccessToken", func() {
		It("sets the authentication token information", func() {
			var config Config
			config.SetAccessToken("I am the access token")
			Expect(config.ConfigFile.AccessToken).To(Equal("I am the access token"))
		})
	})

	Describe("SetOrganizationInformation", func() {
		It("sets the organization GUID and name", func() {
			config := Config{}
			config.SetOrganizationInformation("guid-value-1", "my-org-name")

			Expect(config.ConfigFile.TargetedOrganization.GUID).To(Equal("guid-value-1"))
			Expect(config.ConfigFile.TargetedOrganization.Name).To(Equal("my-org-name"))
		})
	})

	Describe("SetRefreshToken", func() {
		It("sets the refresh token information", func() {
			var config Config
			config.SetRefreshToken("I am the refresh token")
			Expect(config.ConfigFile.RefreshToken).To(Equal("I am the refresh token"))
		})
	})

	Describe("SetSpaceInformation", func() {
		It("sets the space GUID, name, and AllowSSH", func() {
			config := Config{}
			config.SetSpaceInformation("guid-value-1", "my-org-name", true)

			Expect(config.ConfigFile.TargetedSpace.GUID).To(Equal("guid-value-1"))
			Expect(config.ConfigFile.TargetedSpace.Name).To(Equal("my-org-name"))
			Expect(config.ConfigFile.TargetedSpace.AllowSSH).To(BeTrue())
		})
	})

	Describe("SetTargetInformation", func() {
		It("sets the api target and other related endpoints", func() {
			config := Config{
				ConfigFile: JSONConfig{
					TargetedOrganization: Organization{
						GUID: "this-is-a-guid",
						Name: "jo bobo jim boo",
					},
					TargetedSpace: Space{
						GUID:     "this-is-a-guid",
						Name:     "jo bobo jim boo",
						AllowSSH: true,
					},
				},
			}
			config.SetTargetInformation(
				"https://api.foo.com",
				"2.59.31",
				"https://login.foo.com",
				"2.0.0",
				"wws://doppler.foo.com:443",
				"https://api.foo.com/routing",
				true,
			)

			Expect(config.ConfigFile.Target).To(Equal("https://api.foo.com"))
			Expect(config.ConfigFile.APIVersion).To(Equal("2.59.31"))
			Expect(config.ConfigFile.AuthorizationEndpoint).To(Equal("https://login.foo.com"))
			Expect(config.ConfigFile.MinCLIVersion).To(Equal("2.0.0"))
			Expect(config.ConfigFile.DopplerEndpoint).To(Equal("wws://doppler.foo.com:443"))
			Expect(config.ConfigFile.RoutingEndpoint).To(Equal("https://api.foo.com/routing"))
			Expect(config.ConfigFile.SkipSSLValidation).To(BeTrue())

			Expect(config.ConfigFile.TargetedOrganization.GUID).To(BeEmpty())
			Expect(config.ConfigFile.TargetedOrganization.Name).To(BeEmpty())
			Expect(config.ConfigFile.TargetedSpace.GUID).To(BeEmpty())
			Expect(config.ConfigFile.TargetedSpace.Name).To(BeEmpty())
			Expect(config.ConfigFile.TargetedSpace.AllowSSH).To(BeFalse())
		})
	})

	Describe("SetTokenInformation", func() {
		It("sets the authentication token information", func() {
			var config Config
			config.SetTokenInformation("I am the access token", "I am the refresh token", "I am the SSH OAuth client")

			Expect(config.ConfigFile.AccessToken).To(Equal("I am the access token"))
			Expect(config.ConfigFile.RefreshToken).To(Equal("I am the refresh token"))
			Expect(config.ConfigFile.SSHOAuthClient).To(Equal("I am the SSH OAuth client"))
		})
	})

	Describe("SetUAAEndpoint", func() {
		It("sets the UAA endpoint", func() {
			var config Config
			config.SetUAAEndpoint("some-uaa-endpoint.com")
			Expect(config.ConfigFile.UAAEndpoint).To(Equal("some-uaa-endpoint.com"))
		})
	})

	Describe("SkipSSLValidation", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "SSLDisabled":true }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns fields directly from config", func() {
			Expect(config.SkipSSLValidation()).To(BeTrue())
		})
	})

	Describe("SSHOAuthClient", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "SSHOAuthClient":"some-ssh-client" }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns the client ID", func() {
			Expect(config.SSHOAuthClient()).To(Equal("some-ssh-client"))
		})
	})

	Describe("Target", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "Target":"https://api.foo.com" }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns the target", func() {
			Expect(config.Target()).To(Equal("https://api.foo.com"))
		})
	})

	Describe("TargetedOrganization", func() {
		It("returns the organization", func() {
			organization := Organization{
				GUID: "some-guid",
				Name: "some-org",
			}
			config := Config{
				ConfigFile: JSONConfig{
					TargetedOrganization: organization,
				},
			}

			Expect(config.TargetedOrganization()).To(Equal(organization))
		})
	})

	Describe("TargetedSpace", func() {
		It("returns the space", func() {
			space := Space{
				GUID: "some-guid",
				Name: "some-space",
			}
			config := Config{
				ConfigFile: JSONConfig{
					TargetedSpace: space,
				},
			}

			Expect(config.TargetedSpace()).To(Equal(space))
		})
	})

	Describe("UAAOAuthClient", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `{ "UAAOAuthClient":"some-client" }`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns the client ID", func() {
			Expect(config.UAAOAuthClient()).To(Equal("some-client"))
		})
	})

	Describe("UAAOAuthClientSecret", func() {
		var config *Config

		BeforeEach(func() {
			rawConfig := `
					{
						"UAAOAuthClient": "some-client-id",
						"UAAOAuthClientSecret": "some-client-secret"
					}`
			setConfig(homeDir, rawConfig)

			var err error
			config, err = LoadConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config).ToNot(BeNil())
		})

		It("returns the client secret", func() {
			Expect(config.UAAOAuthClientSecret()).To(Equal("some-client-secret"))
		})
	})

	Describe("UnsetOrganizationInformation", func() {
		config := Config{}
		BeforeEach(func() {
			config.SetOrganizationInformation("some-org-guid", "some-org")
		})

		It("resets the org GUID and name", func() {
			config.UnsetOrganizationInformation()

			Expect(config.ConfigFile.TargetedOrganization.GUID).To(Equal(""))
			Expect(config.ConfigFile.TargetedOrganization.Name).To(Equal(""))
		})
	})

	Describe("UnsetSpaceInformation", func() {
		config := Config{}
		BeforeEach(func() {
			config.SetSpaceInformation("guid-value-1", "my-org-name", true)
		})

		It("resets the space GUID, name, and AllowSSH to default values", func() {
			config.UnsetSpaceInformation()

			Expect(config.ConfigFile.TargetedSpace.GUID).To(Equal(""))
			Expect(config.ConfigFile.TargetedSpace.Name).To(Equal(""))
			Expect(config.ConfigFile.TargetedSpace.AllowSSH).To(BeFalse())
		})
	})
})
