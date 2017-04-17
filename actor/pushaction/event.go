package pushaction

type Event string

const (
	ApplicationCreated   Event = "application created"
	ApplicationUpdated   Event = "application updated"
	RouteCreated         Event = "route created"
	RouteBound           Event = "route bound"
	UploadingApplication Event = "uploading application"
	UploadComplete       Event = "upload complete"
	Complete             Event = "complete"
)
