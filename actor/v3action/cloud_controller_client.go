package v3action

import (
	"net/url"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
)

//go:generate counterfeiter . CloudControllerClient

// CloudControllerClient is the interface to the cloud controller V3 API.
type CloudControllerClient interface {
	AssignSpaceToIsolationSegment(spaceGUID string, isolationSegmentGUID string) (ccv3.Relationship, ccv3.Warnings, error)
	CloudControllerAPIVersion() string
	CreateApplication(app ccv3.Application) (ccv3.Application, ccv3.Warnings, error)
	CreateIsolationSegment(name string) (ccv3.IsolationSegment, ccv3.Warnings, error)
	DeleteIsolationSegment(guid string) (ccv3.Warnings, error)
	EntitleIsolationSegmentToOrganizations(isoGUID string, orgGUIDs []string) (ccv3.RelationshipList, ccv3.Warnings, error)
	GetApplications(query url.Values) ([]ccv3.Application, ccv3.Warnings, error)
	GetApplicationTasks(appGUID string, query url.Values) ([]ccv3.Task, ccv3.Warnings, error)
	GetIsolationSegment(guid string) (ccv3.IsolationSegment, ccv3.Warnings, error)
	GetIsolationSegmentOrganizationsByIsolationSegment(isolationSegmentGUID string) ([]ccv3.Organization, ccv3.Warnings, error)
	GetIsolationSegments(query url.Values) ([]ccv3.IsolationSegment, ccv3.Warnings, error)
	GetOrganizations(query url.Values) ([]ccv3.Organization, ccv3.Warnings, error)
	GetSpaceIsolationSegment(spaceGUID string) (ccv3.Relationship, ccv3.Warnings, error)
	NewTask(appGUID string, command string, name string, memory uint64, disk uint64) (ccv3.Task, ccv3.Warnings, error)
	RevokeIsolationSegmentFromOrganization(isolationSegmentGUID string, organizationGUID string) (ccv3.Warnings, error)
	UpdateTask(taskGUID string) (ccv3.Task, ccv3.Warnings, error)
}
