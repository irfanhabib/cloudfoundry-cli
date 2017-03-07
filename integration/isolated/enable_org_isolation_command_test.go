package isolated

import (
	"code.cloudfoundry.org/cli/integration/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("enable-org-isolation command", func() {
	var isolationSegmentName string
	var organizationName string

	BeforeEach(func() {
		isolationSegmentName = helpers.IsolationSegmentName()
		organizationName = helpers.NewOrgName()
	})

	Describe("help", func() {
		Context("when --help flag is set", func() {
			It("Displays command usage to output", func() {
				session := helpers.CF("enable-org-isolation", "--help")
				Eventually(session).Should(Say("NAME:"))
				Eventually(session).Should(Say("enable-org-isolation - Entitle an organization to an isolation segment"))
				Eventually(session).Should(Say("USAGE:"))
				Eventually(session).Should(Say("cf enable-org-isolation ORG_NAME SEGMENT_NAME"))
				Eventually(session).Should(Say("SEE ALSO:"))
				Eventually(session).Should(Say("create-isolation-segment, isolation-segments"))
				Eventually(session).Should(Exit(0))
			})
		})
	})

	Context("when the environment is not setup correctly", func() {
		Context("when no API endpoint is set", func() {
			BeforeEach(func() {
				helpers.UnsetAPI()
			})

			It("fails with no API endpoint set message", func() {
				session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
				Eventually(session).Should(Say("FAILED"))
				Eventually(session.Err).Should(Say("No API endpoint set. Use 'cf login' or 'cf api' to target an endpoint."))
				Eventually(session).Should(Exit(1))
			})
		})

		Context("when not logged in", func() {
			BeforeEach(func() {
				helpers.LogoutCF()
			})

			It("fails with not logged in message", func() {
				session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
				Eventually(session).Should(Say("FAILED"))
				Eventually(session.Err).Should(Say("Not logged in. Use 'cf login' to log in."))
				Eventually(session).Should(Exit(1))
			})
		})
	})

	Context("when the environment is set up correctly", func() {
		var userName string

		BeforeEach(func() {
			helpers.LoginCF()
			userName, _ = helpers.GetCredentials()
		})

		Context("when the isolation segment does not exist", func() {
			It("fails with isolation segment not found message", func() {
				session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
				Eventually(session).Should(Say("Enabling isolation segment %s for org %s as %s…", isolationSegmentName, organizationName, userName))
				Eventually(session).Should(Say("FAILED"))
				Eventually(session.Err).Should(Say("Isolation segment '%s' not found.", isolationSegmentName))
				Eventually(session).Should(Exit(1))
			})
		})

		Context("when the isolation segment exists", func() {
			BeforeEach(func() {
				Eventually(helpers.CF("create-isolation-segment", isolationSegmentName)).Should(Exit(0))
			})

			// TODO: Delete this and add it to cleanup script after #138303919
			AfterEach(func() {
				Eventually(helpers.CF("delete-org", "-f", organizationName)).Should(Exit(0))
				Eventually(helpers.CF("delete-isolation-segment", "-f", isolationSegmentName)).Should(Exit(0))
			})

			Context("when the organization does not exist", func() {
				It("fails with organization not found message", func() {
					session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
					Eventually(session).Should(Say("Enabling isolation segment %s for org %s as %s…", isolationSegmentName, organizationName, userName))
					Eventually(session).Should(Say("FAILED"))
					Eventually(session.Err).Should(Say("Organization '%s' not found.", organizationName))
					Eventually(session).Should(Exit(1))
				})
			})

			Context("when the organization exists", func() {
				BeforeEach(func() {
					helpers.CreateOrg(organizationName)
					helpers.TargetOrg(organizationName)
				})

				It("displays OK", func() {
					session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
					Eventually(session).Should(Say("Enabling isolation segment %s for org %s as %s…", isolationSegmentName, organizationName, userName))
					Eventually(session).Should(Say("OK"))
					Eventually(session).Should(Exit(0))
				})

				Context("when the isolation is already enabled", func() {
					BeforeEach(func() {
						Eventually(helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)).Should(Exit(0))
					})

					It("displays OK", func() {
						session := helpers.CF("enable-org-isolation", isolationSegmentName, organizationName)
						Eventually(session).Should(Say("Enabling isolation segment %s for org %s as %s…", isolationSegmentName, organizationName, userName))
						Eventually(session).Should(Say("OK"))
						Eventually(session).Should(Exit(0))
					})
				})
			})
		})
	})
})
