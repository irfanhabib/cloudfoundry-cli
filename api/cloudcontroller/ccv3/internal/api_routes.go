package internal

import "net/http"

// Naming convention:
//
// Method + non-parameter parts of the path
//
// If the request returns a single entity by GUID, use the singular (for example
// /v2/organizations/:organization_guid is GetOrganization).
//
// The const name should always be the const value + Request.
const (
	DeleteApplicationProcessInstanceRequest                 = "DeleteApplicationProcessInstanceRequest"
	DeleteApplicationRequest                                = "DeleteApplication"
	DeleteIsolationSegmentRelationshipOrganizationRequest   = "DeleteIsolationSegmentRelationshipOrganization"
	DeleteIsolationSegmentRequest                           = "DeleteIsolationSegment"
	GetAppDropletsRequest                                   = "GetAppDroplets"
	GetAppProcessesRequest                                  = "GetAppProcesses"
	GetAppTasksRequest                                      = "GetAppTasks"
	GetApplicationEnvironmentVariables                      = "GetApplicationEnvironmentVariables"
	GetApplicationProcessByTypeRequest                      = "GetApplicationProcessByType"
	GetAppsRequest                                          = "GetApps"
	GetBuildRequest                                         = "GetBuild"
	GetDropletRequest                                       = "GetDroplet"
	GetIsolationSegmentOrganizationsRequest                 = "GetIsolationSegmentRelationshipOrganizations"
	GetIsolationSegmentRequest                              = "GetIsolationSegment"
	GetIsolationSegmentsRequest                             = "GetIsolationSegments"
	GetOrganizationDefaultIsolationSegmentRequest           = "GetOrganizationDefaultIsolationSegment"
	GetOrgsRequest                                          = "GetOrgs"
	GetSpacesRequest                                        = "GetSpaces"
	GetPackageRequest                                       = "GetPackage"
	GetPackagesRequest                                      = "GetPackages"
	GetProcessInstancesRequest                              = "GetProcessInstances"
	GetSpaceRelationshipIsolationSegmentRequest             = "GetSpaceRelationshipIsolationSegmentRequest"
	PatchApplicationCurrentDropletRequest                   = "PatchApplicationCurrentDroplet"
	PatchApplicationUserProvidedEnvironmentVariablesRequest = "PatchApplicationUserProvidedEnvironmentVariablesRequest"
	PatchApplicationProcessHealthCheckRequest               = "PatchApplicationProcessHealthCheck"
	PatchApplicationRequest                                 = "PatchApplicationRequest"
	PatchOrganizationDefaultIsolationSegmentRequest         = "PatchOrganizationDefaultIsolationSegmentRequest"
	PatchSpaceRelationshipIsolationSegmentRequest           = "PatchSpaceRelationshipIsolationSegmentRequest"
	PostAppTasksRequest                                     = "PostAppTasks"
	PostApplicationProcessScaleRequest                      = "PostApplicationProcessScale"
	PostApplicationRequest                                  = "PostApplicationRequest"
	PostApplicationStartRequest                             = "PostApplicationStart"
	PostApplicationStopRequest                              = "PostApplicationStop"
	PostBuildRequest                                        = "PostBuild"
	PostIsolationSegmentRelationshipOrganizationsRequest    = "PostIsolationSegmentRelationshipOrganizations"
	PostIsolationSegmentsRequest                            = "PostIsolationSegments"
	PostPackageRequest                                      = "PostPackageRequest"
	PutTaskCancelRequest                                    = "PutTaskCancelRequest"
)

const (
	AppsResource              = "apps"
	BuildsResource            = "builds"
	DropletsResource          = "droplets"
	IsolationSegmentsResource = "isolation_segments"
	OrgsResource              = "organizations"
	PackagesResource          = "packages"
	ProcessesResource         = "processes"
	SpacesResource            = "spaces"
	TasksResource             = "tasks"
)

// APIRoutes is a list of routes used by the router to construct request URLs.
var APIRoutes = []Route{
	{Path: "/", Method: http.MethodGet, Name: GetAppsRequest, Resource: AppsResource},
	{Path: "/", Method: http.MethodGet, Name: GetIsolationSegmentsRequest, Resource: IsolationSegmentsResource},
	{Path: "/", Method: http.MethodGet, Name: GetOrgsRequest, Resource: OrgsResource},
	{Path: "/", Method: http.MethodGet, Name: GetSpacesRequest, Resource: SpacesResource},
	{Path: "/", Method: http.MethodGet, Name: GetPackagesRequest, Resource: PackagesResource},
	{Path: "/", Method: http.MethodPost, Name: PostApplicationRequest, Resource: AppsResource},
	{Path: "/", Method: http.MethodPost, Name: PostBuildRequest, Resource: BuildsResource},
	{Path: "/", Method: http.MethodPost, Name: PostIsolationSegmentsRequest, Resource: IsolationSegmentsResource},
	{Path: "/", Method: http.MethodPost, Name: PostPackageRequest, Resource: PackagesResource},
	{Path: "/:app_guid", Method: http.MethodDelete, Name: DeleteApplicationRequest, Resource: AppsResource},
	{Path: "/:app_guid", Method: http.MethodPatch, Name: PatchApplicationRequest, Resource: AppsResource},
	{Path: "/:app_guid/actions/start", Method: http.MethodPost, Name: PostApplicationStartRequest, Resource: AppsResource},
	{Path: "/:app_guid/actions/stop", Method: http.MethodPost, Name: PostApplicationStopRequest, Resource: AppsResource},
	{Path: "/:app_guid/droplets", Method: http.MethodGet, Name: GetAppDropletsRequest, Resource: AppsResource},
	{Path: "/:app_guid/env", Method: http.MethodGet, Name: GetApplicationEnvironmentVariables, Resource: AppsResource},
	{Path: "/:app_guid/environment_variables", Method: http.MethodPatch, Name: PatchApplicationUserProvidedEnvironmentVariablesRequest, Resource: AppsResource},
	{Path: "/:app_guid/processes", Method: http.MethodGet, Name: GetAppProcessesRequest, Resource: AppsResource},
	{Path: "/:app_guid/processes/:type", Method: http.MethodGet, Name: GetApplicationProcessByTypeRequest, Resource: AppsResource},
	{Path: "/:app_guid/processes/:type/actions/scale", Method: http.MethodPost, Name: PostApplicationProcessScaleRequest, Resource: AppsResource},
	{Path: "/:app_guid/processes/:type/instances/:index", Method: http.MethodDelete, Name: DeleteApplicationProcessInstanceRequest, Resource: AppsResource},
	{Path: "/:app_guid/relationships/current_droplet", Method: http.MethodPatch, Name: PatchApplicationCurrentDropletRequest, Resource: AppsResource},
	{Path: "/:app_guid/tasks", Method: http.MethodGet, Name: GetAppTasksRequest, Resource: AppsResource},
	{Path: "/:app_guid/tasks", Method: http.MethodPost, Name: PostAppTasksRequest, Resource: AppsResource},
	{Path: "/:build_guid", Method: http.MethodGet, Name: GetBuildRequest, Resource: BuildsResource},
	{Path: "/:droplet_guid", Method: http.MethodGet, Name: GetDropletRequest, Resource: DropletsResource},
	{Path: "/:isolation_segment_guid", Method: http.MethodDelete, Name: DeleteIsolationSegmentRequest, Resource: IsolationSegmentsResource},
	{Path: "/:isolation_segment_guid", Method: http.MethodGet, Name: GetIsolationSegmentRequest, Resource: IsolationSegmentsResource},
	{Path: "/:isolation_segment_guid/organizations", Method: http.MethodGet, Name: GetIsolationSegmentOrganizationsRequest, Resource: IsolationSegmentsResource},
	{Path: "/:isolation_segment_guid/relationships/organizations", Method: http.MethodPost, Name: PostIsolationSegmentRelationshipOrganizationsRequest, Resource: IsolationSegmentsResource},
	{Path: "/:isolation_segment_guid/relationships/organizations/:organization_guid", Method: http.MethodDelete, Name: DeleteIsolationSegmentRelationshipOrganizationRequest, Resource: IsolationSegmentsResource},
	{Path: "/:organization_guid/relationships/default_isolation_segment", Method: http.MethodGet, Name: GetOrganizationDefaultIsolationSegmentRequest, Resource: OrgsResource},
	{Path: "/:organization_guid/relationships/default_isolation_segment", Method: http.MethodPatch, Name: PatchOrganizationDefaultIsolationSegmentRequest, Resource: OrgsResource},
	{Path: "/:package_guid", Method: http.MethodGet, Name: GetPackageRequest, Resource: PackagesResource},
	{Path: "/:process_guid", Method: http.MethodPatch, Name: PatchApplicationProcessHealthCheckRequest, Resource: ProcessesResource},
	{Path: "/:process_guid/stats", Method: http.MethodGet, Name: GetProcessInstancesRequest, Resource: ProcessesResource},
	{Path: "/:space_guid/relationships/isolation_segment", Method: http.MethodGet, Name: GetSpaceRelationshipIsolationSegmentRequest, Resource: SpacesResource},
	{Path: "/:space_guid/relationships/isolation_segment", Method: http.MethodPatch, Name: PatchSpaceRelationshipIsolationSegmentRequest, Resource: SpacesResource},
	{Path: "/:task_guid/cancel", Method: http.MethodPut, Name: PutTaskCancelRequest, Resource: TasksResource},
}
