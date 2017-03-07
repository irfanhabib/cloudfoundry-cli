package isolated

import (
	"code.cloudfoundry.org/cli/integration/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("create-isolation-segment command", func() {
	var isolationSegmentName string

	BeforeEach(func() {
		isolationSegmentName = helpers.IsolationSegmentName()
	})

	Describe("help", func() {
		Context("when --help flag is set", func() {
			It("Displays command usage to output", func() {
				session := helpers.CF("create-isolation-segment", "--help")
				Eventually(session).Should(Say("NAME:"))
				Eventually(session).Should(Say("create-isolation-segment - Create an isolation segment"))
				Eventually(session).Should(Say("USAGE:"))
				Eventually(session).Should(Say("cf create-isolation-segment SEGMENT_NAME"))
				Eventually(session).Should(Say("NOTES:"))
				Eventually(session).Should(Say("The isolation segment name must match the placement tag applied to the Diego cell."))
				Eventually(session).Should(Say("SEE ALSO:"))
				Eventually(session).Should(Say("enable-org-isolation, isolation-segments"))
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
				session := helpers.CF("create-isolation-segment", isolationSegmentName)
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
				session := helpers.CF("create-isolation-segment", isolationSegmentName)
				Eventually(session).Should(Say("FAILED"))
				Eventually(session.Err).Should(Say("Not logged in. Use 'cf login' to log in."))
				Eventually(session).Should(Exit(1))
			})
		})
	})

	Context("when the environment is set up correctly", func() {
		BeforeEach(func() {
			helpers.LoginCF()
		})

		// TODO: Delete this and add it to cleanup script after #138303919
		AfterEach(func() {
			Eventually(helpers.CF("delete-isolation-segment", "-f", isolationSegmentName)).Should(Exit(0))
		})

		Context("when the isolation segment does not exist", func() {
			It("creates the isolation segment", func() {
				session := helpers.CF("create-isolation-segment", isolationSegmentName)
				userName, _ := helpers.GetCredentials()
				Eventually(session).Should(Say("Creating isolation segment %s as %s...", isolationSegmentName, userName))
				Eventually(session).Should(Say("OK"))
				Eventually(session).Should(Exit(0))
			})
		})

		Context("when the isolation segment already exists", func() {
			BeforeEach(func() {
				Eventually(helpers.CF("create-isolation-segment", isolationSegmentName)).Should(Exit(0))
			})

			It("returns an ok", func() {
				session := helpers.CF("create-isolation-segment", isolationSegmentName)
				Eventually(session.Err).Should(Say("Isolation segment %s already exists", isolationSegmentName))
				Eventually(session).Should(Say("OK"))
				Eventually(session).Should(Exit(0))
			})
		})
	})
})
