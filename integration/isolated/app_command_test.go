package isolated

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/cli/integration/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("app command", func() {
	BeforeEach(func() {
		Skip("skipping until story #126256629 is finished")
	})

	Describe("help", func() {
		Context("when --help flag is set", func() {
			It("Displays command usage to output", func() {
				session := helpers.CF("app", "--help")
				Eventually(session).Should(Exit(0))
				Expect(session).To(Say("NAME:"))
				Expect(session).To(Say("app - Display health and status for app"))
				Expect(session).To(Say("USAGE:"))
				Expect(session).To(Say("cf app APP_NAME"))
				Expect(session).To(Say("OPTIONS:"))
				Expect(session).To(Say("--guid      Retrieve and display the given app's guid.  All other health and status output for the app is suppressed."))
				Expect(session).To(Say("SEE ALSO:"))
				Expect(session).To(Say("apps, events, logs, map-route, push, unmap-route"))
			})
		})
	})

	Context("when the environment is not setup correctly", func() {
		Context("when no API endpoint is set", func() {
			BeforeEach(func() {
				helpers.UnsetAPI()
			})

			It("fails with no API endpoint set message", func() {
				session := helpers.CF("app", "wut")
				Eventually(session).Should(Exit(1))
				Expect(session).To(Say("FAILED"))
				Expect(session).To(Say("No API endpoint set. Use 'cf login' or 'cf api' to target an endpoint."))
			})
		})

		Context("when not logged in", func() {
			BeforeEach(func() {
				helpers.LogoutCF()
			})

			It("fails with not logged in message", func() {
				session := helpers.CF("app", "wut")
				Eventually(session).Should(Exit(1))
				Expect(session).To(Say("FAILED"))
				Expect(session).To(Say("Not logged in. Use 'cf login' to log in."))
			})
		})

		Context("when there is no org and space set", func() {
			BeforeEach(func() {
				helpers.LogoutCF()
				helpers.LoginCF()
			})

			It("fails with no targeted org error message", func() {
				session := helpers.CF("app", "wut")
				Eventually(session).Should(Exit(1))
				Expect(session).To(Say("FAILED"))
				Expect(session).To(Say("No org and space targeted, use 'cf target -o ORG -s SPACE' to target an org and space"))
			})
		})

		Context("when there is no space set", func() {
			BeforeEach(func() {
				helpers.LogoutCF()
				helpers.LoginCF()
				helpers.TargetOrg(ReadOnlyOrg)
			})

			It("fails with no targeted space error message", func() {
				session := helpers.CF("app", "wut")
				Eventually(session).Should(Exit(1))
				Expect(session).To(Say("FAILED"))
				Expect(session).To(Say("No space targeted, use 'cf target -s SPACE' to target a space."))
			})
		})
	})

	Context("when the environment is set up correctly", func() {
		var (
			orgName   string
			spaceName string
		)

		BeforeEach(func() {
			orgName = helpers.NewOrgName()
			spaceName = helpers.PrefixedRandomName("SPACE")

			setupCF(orgName, spaceName)
		})

		Context("when the app does not exist", func() {
			Context("when no flags are given", func() {
				It("tells the user that the app is not found and exits 1", func() {
					appName := helpers.PrefixedRandomName("app")
					session := helpers.CF("app", appName)

					Eventually(session).Should(Say("FAILED"))
					Eventually(session).Should(Say("App %s not found", appName))
					Eventually(session).Should(Exit(1))
				})
			})

			Context("when the --guid flag is given", func() {
				It("tells the user that the app is not found and exits 1", func() {
					appName := helpers.PrefixedRandomName("app")
					session := helpers.CF("app", "--guid", appName)

					Eventually(session).Should(Say("FAILED"))
					Eventually(session).Should(Say("App %s not found", appName))
					Eventually(session).Should(Exit(1))
				})
			})
		})

		Context("when the app does exist", func() {
			var (
				domainName string
				tcpDomain  helpers.Domain
				appName    string
			)
			BeforeEach(func() {
				appName = helpers.PrefixedRandomName("app")
				domainName = defaultSharedDomain()
				tcpDomain = helpers.NewDomain(orgName, helpers.DomainName("tcp"))
				tcpDomain.CreateWithRouterGroup("default-tcp")
				helpers.WithHelloWorldApp(func(appDir string) {
					manifestContents := []byte(fmt.Sprintf(`
---
applications:
- name: %s
  memory: 128M
  instances: 2
  disk_quota: 128M
  routes:
  - route: %s.%s
  - route: %s:1111
`, appName, appName, domainName, tcpDomain.Name))
					manifestPath := filepath.Join(appDir, "manifest.yml")
					err := ioutil.WriteFile(manifestPath, manifestContents, 0666)
					Expect(err).ToNot(HaveOccurred())

					// Create manifest and add big numbers
					Eventually(helpers.CF("push", appName, "-p", appDir, "-f", manifestPath, "-b", "staticfile_buildpack")).Should(Exit(0))
				})
			})

			AfterEach(func() {
				Eventually(helpers.CF("delete", appName, "-f", "-r")).Should(Exit(0))
			})

			Context("when the app is started and has 2 instances", func() {
				It("displays the app information", func() {
					session := helpers.CF("app", appName)
					Eventually(session).Should(Say("Name:            %s", appName))
					Eventually(session).Should(Say("Requested state: started"))
					Eventually(session).Should(Say("Instances:       2/2"))
					Eventually(session).Should(Say("Usage:           128M x 2 instances"))
					Eventually(session).Should(Say("Routes:          %s.%s, %s:1111", appName, domainName, tcpDomain.Name))
					Eventually(session).Should(Say("Last uploaded:"))
					Eventually(session).Should(Say("Stack:           cflinuxfs2"))
					Eventually(session).Should(Say("Buildpack:       staticfile_buildpack"))

					Eventually(session).Should(Say("State\\s+Since\\s+Cpu\\s+Memory\\s+Disk\\s+Details"))
					Eventually(session).Should(Say("#0\\s+running\\s+.*\\d+\\.\\d+%.*of 128M.*of 128M"))
					Eventually(session).Should(Say("#1\\s+running\\s+.*\\d+\\.\\d+%.*of 128M.*of 128M"))
				})
			})

			Context("when the app is stopped", func() {
				BeforeEach(func() {
					Eventually(helpers.CF("stop", appName)).Should(Exit(0))
				})

				It("displays the app information", func() {
					session := helpers.CF("app", appName)
					Eventually(session).Should(Say("Name:            %s", appName))
					Eventually(session).Should(Say("Requested state: stopped"))
					Eventually(session).Should(Say("Instances:       0/2"))
					Eventually(session).Should(Say("Usage:           128M x 2 instances"))
					Eventually(session).Should(Say("Routes:          %s.%s, %s:1111", appName, domainName, tcpDomain.Name))
					Eventually(session).Should(Say("Last uploaded:"))
					Eventually(session).Should(Say("Stack:           cflinuxfs2"))
					Eventually(session).Should(Say("Buildpack:       staticfile_buildpack"))

					Eventually(session).Should(Say("There are no running instances of this app."))
				})
			})

			Context("when the app has 0 instances", func() {
				BeforeEach(func() {
					Eventually(helpers.CF("scale", appName, "-i", "0")).Should(Exit(0))
				})

				It("displays the app information", func() {
					session := helpers.CF("app", appName)
					Eventually(session).Should(Say("Name:            %s", appName))
					Eventually(session).Should(Say("Requested state: started"))
					Eventually(session).Should(Say("Instances:       0/0"))
					Eventually(session).Should(Say("Usage:           128M x 0 instances"))
					Eventually(session).Should(Say("Routes:          %s.%s, %s:1111", appName, domainName, tcpDomain.Name))
					Eventually(session).Should(Say("Last uploaded:"))
					Eventually(session).Should(Say("Stack:           cflinuxfs2"))
					Eventually(session).Should(Say("Buildpack:       staticfile_buildpack"))

					Eventually(session).Should(Say("There are no running instances of this app."))
				})

			})

			Context("when the --guid flag is given", func() {
				var appGUID string

				BeforeEach(func() {
					session := helpers.CF("curl", fmt.Sprintf("/v2/apps?q=name:%s", appName))
					Eventually(session).Should(Exit(0))
					rawJSON := strings.TrimSpace(string(session.Out.Contents()))
					var AppInfo struct {
						Resources []struct {
							Metadata struct {
								GUID string `json:"guid"`
							} `json:"metadata"`
						} `json:"resources"`
					}

					err := json.Unmarshal([]byte(rawJSON), &AppInfo)
					Expect(err).NotTo(HaveOccurred())

					appGUID = AppInfo.Resources[0].Metadata.GUID
				})

				It("displays the app information", func() {
					session := helpers.CF("app", "--guid", appName)
					Eventually(session).Should(Say(appGUID))
				})
			})
		})
	})
})
