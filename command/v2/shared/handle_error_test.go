package shared_test

import (
	"errors"

	"code.cloudfoundry.org/cli/actor/sharedaction"
	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccerror"
	"code.cloudfoundry.org/cli/api/uaa"
	"code.cloudfoundry.org/cli/command"
	. "code.cloudfoundry.org/cli/command/v2/shared"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("HandleError", func() {
	err := errors.New("some-error")

	DescribeTable("error translations",
		func(passedInErr error, expectedErr error) {
			actualErr := HandleError(passedInErr)
			Expect(actualErr).To(MatchError(expectedErr))
		},

		Entry("ccerror.RequestError -> APIRequestError",
			ccerror.RequestError{Err: err},
			command.APIRequestError{Err: err}),

		Entry("ccerror.UnverifiedServerError -> InvalidSSLCertError",
			ccerror.UnverifiedServerError{URL: "some-url"},
			command.InvalidSSLCertError{API: "some-url"}),

		Entry("ccerror.SSLValidationHostnameError -> SSLCertErrorError",
			ccerror.SSLValidationHostnameError{Message: "some-message"},
			command.SSLCertErrorError{Message: "some-message"}),

		Entry("ccerror.APINotFoundError -> APINotFoundError",
			ccerror.APINotFoundError{URL: "some-url"},
			command.APINotFoundError{URL: "some-url"}),

		Entry("v2action.ApplicationNotFoundError -> ApplicationNotFoundError",
			v2action.ApplicationNotFoundError{Name: "some-app"},
			command.ApplicationNotFoundError{Name: "some-app"}),

		Entry("v2action.SecurityGroupNotFoundError -> SecurityGroupNotFoundError",
			v2action.SecurityGroupNotFoundError{Name: "some-security-group"},
			SecurityGroupNotFoundError{Name: "some-security-group"}),

		Entry("v2action.ServiceInstanceNotFoundError -> ServiceInstanceNotFoundError",
			v2action.ServiceInstanceNotFoundError{Name: "some-service-instance"},
			command.ServiceInstanceNotFoundError{Name: "some-service-instance"}),

		Entry("ccerror.JobFailedError -> JobFailedError",
			ccerror.JobFailedError{JobGUID: "some-job-guid"},
			JobFailedError{JobGUID: "some-job-guid"}),

		Entry("ccerror.JobTimeoutError -> JobTimeoutError",
			ccerror.JobTimeoutError{JobGUID: "some-job-guid"},
			JobTimeoutError{JobGUID: "some-job-guid"}),

		Entry("v2action.OrganizationNotFoundError -> OrgNotFoundError",
			v2action.OrganizationNotFoundError{Name: "some-org"},
			OrganizationNotFoundError{Name: "some-org"}),

		Entry("v2action.SpaceNotFoundError -> SpaceNotFoundError",
			v2action.SpaceNotFoundError{Name: "some-space"},
			SpaceNotFoundError{Name: "some-space"}),

		Entry("sharedaction.NotLoggedInError -> NotLoggedInError",
			sharedaction.NotLoggedInError{BinaryName: "faceman"},
			command.NotLoggedInError{BinaryName: "faceman"}),

		Entry("sharedaction.NoTargetedOrganizationError -> NoTargetedOrganizationError",
			sharedaction.NoTargetedOrganizationError{BinaryName: "faceman"},
			command.NoTargetedOrganizationError{BinaryName: "faceman"}),

		Entry("sharedaction.NoTargetedSpaceError -> NoTargetedSpaceError",
			sharedaction.NoTargetedSpaceError{BinaryName: "faceman"},
			command.NoTargetedSpaceError{BinaryName: "faceman"}),

		Entry("v2action.HTTPHealthCheckInvalidError -> HTTPHealthCheckInvalidError",
			v2action.HTTPHealthCheckInvalidError{},
			HTTPHealthCheckInvalidError{},
		),

		Entry("uaa.InvalidAuthTokenError -> InvalidRefreshTokenError",
			uaa.InvalidAuthTokenError{},
			InvalidRefreshTokenError{},
		),

		Entry("default case -> original error",
			err,
			err),
	)

	It("returns nil for a nil error", func() {
		nilErr := HandleError(nil)
		Expect(nilErr).To(BeNil())
	})
})
