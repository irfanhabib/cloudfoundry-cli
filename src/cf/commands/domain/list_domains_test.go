package domain_test

import (
	"cf/commands/domain"
	"cf/configuration"
	"cf/errors"
	"cf/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	testapi "testhelpers/api"
	testassert "testhelpers/assert"
	testcmd "testhelpers/commands"
	testconfig "testhelpers/configuration"
	testreq "testhelpers/requirements"
	testterm "testhelpers/terminal"
)

var _ = Describe("domains command", func() {
	It("TestListDomainsRequirements", func() {
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true}
		domainRepo := &testapi.FakeDomainRepository{}

		callListDomains([]string{}, reqFactory, domainRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeTrue())

		reqFactory = &testreq.FakeReqFactory{LoginSuccess: false, TargetedOrgSuccess: true}
		callListDomains([]string{}, reqFactory, domainRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())

		reqFactory = &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: false}
		callListDomains([]string{}, reqFactory, domainRepo)
		Expect(testcmd.CommandDidPassRequirements).To(BeFalse())
	})

	It("TestListDomainsFailsWithUsage", func() {
		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true}
		domainRepo := &testapi.FakeDomainRepository{}

		ui := callListDomains([]string{"foo"}, reqFactory, domainRepo)
		Expect(ui.FailedWithUsage).To(BeTrue())
	})

	It("lists private domains", func() {
		orgFields := models.OrganizationFields{}
		orgFields.Name = "my-org"
		orgFields.Guid = "my-org-guid"

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true, OrganizationFields: orgFields}
		domain1 := models.DomainFields{}
		domain1.Shared = true
		domain1.Name = "Domain1"

		domain2 := models.DomainFields{}
		domain2.Shared = false
		domain2.Name = "Domain2"

		domain3 := models.DomainFields{}
		domain3.Shared = false
		domain3.Name = "Domain3"

		domainRepo := &testapi.FakeDomainRepository{
			ListSharedDomainsDomains:        []models.DomainFields{domain1},
			ListPrivateDomainsForOrgDomains: []models.DomainFields{domain2, domain3},
		}

		ui := callListDomains([]string{}, reqFactory, domainRepo)

		Expect(domainRepo.ListPrivateDomainsForOrgGuid).To(Equal("my-org-guid"))

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting domains in org", "my-org", "my-user"},
			{"name", "status"},
			{"Domain1", "shared"},
			{"Domain2", "owned"},
			{"Domain3", "owned"},
		})
	})

	It("TestListDomainsWhenThereAreNone", func() {
		orgFields := models.OrganizationFields{}
		orgFields.Name = "my-org"
		orgFields.Guid = "my-org-guid"

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true, OrganizationFields: orgFields}
		domainRepo := &testapi.FakeDomainRepository{}

		ui := callListDomains([]string{}, reqFactory, domainRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting domains in org", "my-org", "my-user"},
			{"No domains found"},
		})
	})

	It("TestListDomainsSharedDomainsFails", func() {
		orgFields := models.OrganizationFields{}
		orgFields.Name = "my-org"
		orgFields.Guid = "my-org-guid"

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true, OrganizationFields: orgFields}

		domainRepo := &testapi.FakeDomainRepository{
			ListSharedDomainsApiResponse: errors.New("borked!"),
		}
		ui := callListDomains([]string{}, reqFactory, domainRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting domains in org", "my-org", "my-user"},
			{"failed"},
			{"shared domains"},
			{"borked!"},
		})
	})

	It("lists only the domains for the org if the new shared_domains endpoint returns a 404", func() {
		orgFields := models.OrganizationFields{
			Name: "my-org",
			Guid: "my-org-guid",
		}

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true, OrganizationFields: orgFields}

		domainRepo := &testapi.FakeDomainRepository{
			ListSharedDomainsApiResponse: errors.NewHttpError(404, "9003", "something bad happened"),
			ListPrivateDomainsForOrgDomains: []models.DomainFields{
				models.DomainFields{Name: "ze-domain"},
			},
		}
		ui := callListDomains([]string{}, reqFactory, domainRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting domains in org", "my-org", "my-user"},
			{"ze-domain"},
		})
	})

	It("TestListDomainsOrgDomainsFails", func() {
		orgFields := models.OrganizationFields{}
		orgFields.Name = "my-org"
		orgFields.Guid = "my-org-guid"

		reqFactory := &testreq.FakeReqFactory{LoginSuccess: true, TargetedOrgSuccess: true, OrganizationFields: orgFields}

		domainRepo := &testapi.FakeDomainRepository{
			ListPrivateDomainsForOrgApiResponse: errors.New("borked!"),
		}
		ui := callListDomains([]string{}, reqFactory, domainRepo)

		testassert.SliceContains(ui.Outputs, testassert.Lines{
			{"Getting domains in org", "my-org", "my-user"},
			{"failed"},
			{"private domains"},
			{"borked!"},
		})
	})
})

func callListDomains(args []string, reqFactory *testreq.FakeReqFactory, domainRepo *testapi.FakeDomainRepository) (fakeUI *testterm.FakeUI) {
	fakeUI = new(testterm.FakeUI)
	ctxt := testcmd.NewContext("domains", args)

	configRepo := testconfig.NewRepositoryWithAccessToken(configuration.TokenInfo{Username: "my-user"})

	spaceFields := models.SpaceFields{}
	spaceFields.Name = "my-space"

	orgFields := models.OrganizationFields{}
	orgFields.Name = "my-org"

	configRepo.SetSpaceFields(spaceFields)
	configRepo.SetOrganizationFields(orgFields)

	cmd := domain.NewListDomains(fakeUI, configRepo, domainRepo)
	testcmd.RunCommand(cmd, ctxt, reqFactory)
	return
}
