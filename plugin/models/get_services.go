package plugin_models

type GetServices_Model struct {
	GUID             string
	Name             string
	ServicePlan      GetServices_ServicePlan
	Service          GetServices_ServiceFields
	LastOperation    GetServices_LastOperation
	ApplicationNames []string
	IsUserProvided   bool
}

type GetServices_LastOperation struct {
	Type  string
	State string
}

type GetServices_ServicePlan struct {
	GUID string
	Name string
}

type GetServices_ServiceFields struct {
	Name string
}
