package shared_test

import (
	"errors"

	"code.cloudfoundry.org/cli/actor/actionerror"
	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccerror"
	"code.cloudfoundry.org/cli/api/uaa"
	"code.cloudfoundry.org/cli/command/translatableerror"
	. "code.cloudfoundry.org/cli/command/v2/shared"
	"code.cloudfoundry.org/cli/util/manifest"
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

		Entry("actionerror.PropertyCombinationError -> PropertyCombinationError",
			actionerror.PropertyCombinationError{Properties: []string{"property-1", "property-2"}},
			translatableerror.PropertyCombinationError{Properties: []string{"property-1", "property-2"}},
		),

		Entry("actionerror.DockerPasswordNotSetError -> DockerPasswordNotSetError",
			actionerror.DockerPasswordNotSetError{},
			translatableerror.DockerPasswordNotSetError{},
		),

		Entry("ccerror.RequestError -> APIRequestError",
			ccerror.RequestError{Err: err},
			translatableerror.APIRequestError{Err: err}),

		Entry("ccerror.UnverifiedServerError -> InvalidSSLCertError",
			ccerror.UnverifiedServerError{URL: "some-url"},
			translatableerror.InvalidSSLCertError{API: "some-url"}),

		Entry("ccerror.SSLValidationHostnameError -> SSLCertErrorError",
			ccerror.SSLValidationHostnameError{Message: "some-message"},
			translatableerror.SSLCertError{Message: "some-message"}),

		Entry("ccerror.APINotFoundError -> APINotFoundError",
			ccerror.APINotFoundError{URL: "some-url"},
			translatableerror.APINotFoundError{URL: "some-url"}),

		Entry("v2action.ApplicationNotFoundError -> ApplicationNotFoundError",
			actionerror.ApplicationNotFoundError{Name: "some-app"},
			translatableerror.ApplicationNotFoundError{Name: "some-app"}),

		Entry("actionerror.SecurityGroupNotFoundError -> SecurityGroupNotFoundError",
			actionerror.SecurityGroupNotFoundError{Name: "some-security-group"},
			translatableerror.SecurityGroupNotFoundError{Name: "some-security-group"}),

		Entry("v2action.ServiceInstanceNotFoundError -> ServiceInstanceNotFoundError",
			v2action.ServiceInstanceNotFoundError{Name: "some-service-instance"},
			translatableerror.ServiceInstanceNotFoundError{Name: "some-service-instance"}),

		Entry("v2action.StackNotFoundError -> StackNotFoundError",
			v2action.StackNotFoundError{Name: "some-stack-name", GUID: "some-stack-guid"},
			translatableerror.StackNotFoundError{Name: "some-stack-name", GUID: "some-stack-guid"}),

		Entry("ccerror.JobFailedError -> JobFailedError",
			ccerror.JobFailedError{JobGUID: "some-job-guid", Message: "some-message"},
			translatableerror.JobFailedError{JobGUID: "some-job-guid", Message: "some-message"}),

		Entry("ccerror.JobTimeoutError -> JobTimeoutError",
			ccerror.JobTimeoutError{JobGUID: "some-job-guid"},
			translatableerror.JobTimeoutError{JobGUID: "some-job-guid"}),

		Entry("v2action.OrganizationNotFoundError -> OrgNotFoundError",
			v2action.OrganizationNotFoundError{Name: "some-org"},
			translatableerror.OrganizationNotFoundError{Name: "some-org"}),

		Entry("v2action.SpaceNotFoundError -> SpaceNotFoundError",
			v2action.SpaceNotFoundError{Name: "some-space"},
			translatableerror.SpaceNotFoundError{Name: "some-space"}),

		Entry("actionerror.NotLoggedInError -> NotLoggedInError",
			actionerror.NotLoggedInError{BinaryName: "faceman"},
			translatableerror.NotLoggedInError{BinaryName: "faceman"}),

		Entry("actionerror.NoOrganizationTargetedError -> NoOrganizationTargetedError",
			actionerror.NoOrganizationTargetedError{BinaryName: "faceman"},
			translatableerror.NoOrganizationTargetedError{BinaryName: "faceman"}),

		Entry("actionerror.NoSpaceTargetedError -> NoSpaceTargetedError",
			actionerror.NoSpaceTargetedError{BinaryName: "faceman"},
			translatableerror.NoSpaceTargetedError{BinaryName: "faceman"}),

		Entry("v2action.HTTPHealthCheckInvalidError -> HTTPHealthCheckInvalidError",
			actionerror.HTTPHealthCheckInvalidError{},
			translatableerror.HTTPHealthCheckInvalidError{},
		),

		Entry("v2action.RouteInDifferentSpaceError -> RouteInDifferentSpaceError",
			v2action.RouteInDifferentSpaceError{Route: "some-route"},
			translatableerror.RouteInDifferentSpaceError{Route: "some-route"},
		),

		Entry("v2action.FileChangedError -> FileChangedError",
			v2action.FileChangedError{Filename: "some-filename"},
			translatableerror.FileChangedError{Filename: "some-filename"},
		),

		Entry("v2action.EmptyDirectoryError -> EmptyDirectoryError",
			actionerror.EmptyDirectoryError{Path: "some-filename"},
			translatableerror.EmptyDirectoryError{Path: "some-filename"},
		),

		Entry("actionerror.DomainNotFoundError -> DomainNotFoundError",
			actionerror.DomainNotFoundError{Name: "some-domain-name", GUID: "some-domain-guid"},
			translatableerror.DomainNotFoundError{Name: "some-domain-name", GUID: "some-domain-guid"},
		),

		Entry("actionerror.NoMatchingDomainError -> NoMatchingDomainError",
			actionerror.NoMatchingDomainError{Route: "some-route.com"},
			translatableerror.NoMatchingDomainError{Route: "some-route.com"},
		),

		Entry("uaa.BadCredentialsError -> BadCredentialsError",
			uaa.BadCredentialsError{},
			translatableerror.BadCredentialsError{},
		),

		Entry("uaa.InvalidAuthTokenError -> InvalidRefreshTokenError",
			uaa.InvalidAuthTokenError{},
			translatableerror.InvalidRefreshTokenError{},
		),

		Entry("actionerror.AppNotFoundInManifestError -> AppNotFoundInManifestError",
			actionerror.AppNotFoundInManifestError{Name: "some-app"},
			translatableerror.AppNotFoundInManifestError{Name: "some-app"},
		),

		Entry("actionerror.NoDomainsFoundError -> NoDomainsFoundError",
			actionerror.NoDomainsFoundError{OrganizationGUID: "some-guid"},
			translatableerror.NoDomainsFoundError{},
		),

		Entry("actionerror.NoHostnameAndSharedDomainError -> NoHostnameAndSharedDomainError",
			actionerror.NoHostnameAndSharedDomainError{},
			translatableerror.NoHostnameAndSharedDomainError{},
		),

		Entry("actionerror.InvalidHTTPRouteSettings -> PortNotAllowedWithHTTPDomainError",
			actionerror.InvalidHTTPRouteSettings{Domain: "some-domain"},
			translatableerror.PortNotAllowedWithHTTPDomainError{Domain: "some-domain"},
		),

		Entry("actionerror.MissingNameError -> RequiredNameForPushError",
			actionerror.MissingNameError{},
			translatableerror.RequiredNameForPushError{},
		),

		Entry("actionerror.UploadFailedError -> UploadFailedError",
			actionerror.UploadFailedError{Err: actionerror.NoDomainsFoundError{}},
			translatableerror.UploadFailedError{Err: translatableerror.NoDomainsFoundError{}},
		),

		Entry("actionerror.NonexistentAppPathError -> FileNotFoundError",
			actionerror.NonexistentAppPathError{Path: "some-path"},
			translatableerror.FileNotFoundError{Path: "some-path"},
		),

		Entry("actionerror.CommandLineOptionsWithMultipleAppsError -> CommandLineArgsWithMultipleAppsError",
			actionerror.CommandLineOptionsWithMultipleAppsError{},
			translatableerror.CommandLineArgsWithMultipleAppsError{},
		),

		Entry("manifest.ManifestCreationError -> ManifestCreationError",
			manifest.ManifestCreationError{Err: errors.New("some-error")},
			translatableerror.ManifestCreationError{Err: errors.New("some-error")},
		),

		Entry("uaa.InsufficientScopeError -> UnauthorizedToPerformActionError",
			uaa.InsufficientScopeError{},
			translatableerror.UnauthorizedToPerformActionError{},
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
