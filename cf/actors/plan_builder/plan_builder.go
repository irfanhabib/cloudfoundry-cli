package plan_builder

import (
	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/models"
)

type PlanBuilder interface {
	AttachOrgsToPlans([]models.ServicePlanFields) ([]models.ServicePlanFields, error)
	GetPlansForService(string) ([]models.ServicePlanFields, error)
	GetPlansVisibleToOrg(string) ([]models.ServicePlanFields, error)
}

var (
	OrgToPlansVisibilityMap *map[string][]string
	PlanToOrgsVisibilityMap *map[string][]string
)

type Builder struct {
	servicePlanRepo           api.ServicePlanRepository
	servicePlanVisibilityRepo api.ServicePlanVisibilityRepository
	orgRepo                   api.OrganizationRepository
}

func NewBuilder(plan api.ServicePlanRepository, vis api.ServicePlanVisibilityRepository, org api.OrganizationRepository) Builder {
	return Builder{
		servicePlanRepo:           plan,
		servicePlanVisibilityRepo: vis,
		orgRepo:                   org,
	}
}

func (builder Builder) AttachOrgsToPlans(plans []models.ServicePlanFields) ([]models.ServicePlanFields, error) {
	visMap, err := builder.buildPlanToOrgsVisibilityMap()
	if err != nil {
		return nil, err
	}
	for planIndex, _ := range plans {
		plan := &plans[planIndex]
		plan.OrgNames = visMap[plan.Guid]
	}

	return plans, nil
}

func (builder Builder) GetPlansForService(serviceGuid string) ([]models.ServicePlanFields, error) {
	plans, err := builder.servicePlanRepo.Search(map[string]string{"service_guid": serviceGuid})
	if err != nil {
		return nil, err
	}

	plans, err = builder.AttachOrgsToPlans(plans)
	if err != nil {
		return nil, err
	}
	return plans, nil
}

func (builder Builder) GetPlansVisibleToOrg(orgName string) ([]models.ServicePlanFields, error) {
	var plansToReturn []models.ServicePlanFields
	allPlans, err := builder.servicePlanRepo.Search(nil)

	planToOrgsVisMap, err := builder.buildPlanToOrgsVisibilityMap()
	if err != nil {
		return nil, err
	}

	orgToPlansVisMap := builder.buildOrgToPlansVisibilityMap(planToOrgsVisMap)

	filterOrgPlans := orgToPlansVisMap[orgName]

	for _, plan := range allPlans {
		if builder.containsGuid(filterOrgPlans, plan.Guid) {
			plan.OrgNames = planToOrgsVisMap[plan.Guid]
			plansToReturn = append(plansToReturn, plan)
		} else if plan.Public {
			plansToReturn = append(plansToReturn, plan)
		}
	}

	return plansToReturn, nil
}

func (builder Builder) containsGuid(guidSlice []string, guid string) bool {
	for _, g := range guidSlice {
		if g == guid {
			return true
		}
	}
	return false
}

func (builder Builder) buildPlanToOrgsVisibilityMap() (map[string][]string, error) {
	// Since this map doesn't ever change, we memoize it for performance
	if PlanToOrgsVisibilityMap == nil {
		orgLookup := make(map[string]string)
		builder.orgRepo.ListOrgs(func(org models.Organization) bool {
			orgLookup[org.Guid] = org.Name
			return true
		})

		visibilities, err := builder.servicePlanVisibilityRepo.List()
		if err != nil {
			return nil, err
		}

		visMap := make(map[string][]string)
		for _, vis := range visibilities {
			visMap[vis.ServicePlanGuid] = append(visMap[vis.ServicePlanGuid], orgLookup[vis.OrganizationGuid])
		}
		PlanToOrgsVisibilityMap = &visMap
	}

	return *PlanToOrgsVisibilityMap, nil
}

func (builder Builder) buildOrgToPlansVisibilityMap(planToOrgsMap map[string][]string) map[string][]string {
	// Since this map doesn't ever change, we memoize it for performance
	if OrgToPlansVisibilityMap == nil {
		visMap := make(map[string][]string)
		for planGuid, orgNames := range planToOrgsMap {
			for _, orgName := range orgNames {
				visMap[orgName] = append(visMap[orgName], planGuid)
			}
		}
		OrgToPlansVisibilityMap = &visMap
	}

	return *OrgToPlansVisibilityMap
}
