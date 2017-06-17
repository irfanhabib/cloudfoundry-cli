package command_test

import (
	"bytes"
	"text/template"

	. "code.cloudfoundry.org/cli/command"
	"code.cloudfoundry.org/cli/util/ui"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Translatable Errors", func() {
	translateFunc := func(s string, vars ...interface{}) string {
		formattedTemplate, err := template.New("test template").Parse(s)
		Expect(err).ToNot(HaveOccurred())
		formattedTemplate.Option("missingkey=error")

		var buffer bytes.Buffer
		err = formattedTemplate.Execute(&buffer, vars[0])
		Expect(err).ToNot(HaveOccurred())

		return buffer.String()
	}

	DescribeTable("translates error",
		func(e error) {
			err, ok := e.(ui.TranslatableError)
			Expect(ok).To(BeTrue())
			err.Translate(translateFunc)
		},

		// Command prerequisite errors.
		Entry("NoAPISetError", NoAPISetError{}),
		Entry("NoTargetedOrganizationError", NoTargetedOrganizationError{}),
		Entry("NoTargetedSpaceError", NoTargetedSpaceError{}),
		Entry("NotLoggedInError", NotLoggedInError{}),

		// UAA errors.
		Entry("BadCredentialsError", BadCredentialsError{}),

		// Cloud Controller errors.
		Entry("APIRequestError", APIRequestError{}),
		Entry("InvalidSSLCertError", InvalidSSLCertError{}),
		Entry("SSLCertErrorError", SSLCertErrorError{}),
		Entry("APINotFoundError", APINotFoundError{}),

		// Actor errors.
		Entry("ApplicationNotFoundError", ApplicationNotFoundError{}),
		Entry("ServiceInstanceNotFoundError", ServiceInstanceNotFoundError{}),

		// Parse errors.
		Entry("ArgumentCombinationError", ArgumentCombinationError{}),
		Entry("ParseArgumentError", ParseArgumentError{}),
		Entry("RequiredArgumentError", RequiredArgumentError{}),
		Entry("ThreeRequiredArgumentsError", ThreeRequiredArgumentsError{}),

		// Version errors.
		Entry("MinimumAPIVersionNotMetError", MinimumAPIVersionNotMetError{}),
		Entry("LifecycleMinimumAPIVersionNotMetError", LifecycleMinimumAPIVersionNotMetError{}),
		Entry("HealthCheckTypeUnsupportedError", HealthCheckTypeUnsupportedError{
			SupportedTypes: []string{"some-type", "another-type"},
		}),

		// URL scheme errors.
		Entry("UnsupportedURLSchemeError", UnsupportedURLSchemeError{}),
	)
})
