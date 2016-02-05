package service_test

import (
	"fmt"
	"io/ioutil"
	"os"

	testapi "github.com/cloudfoundry/cli/cf/api/fakes"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/models"
	testcmd "github.com/cloudfoundry/cli/testhelpers/commands"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testreq "github.com/cloudfoundry/cli/testhelpers/requirements"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	"github.com/cloudfoundry/cli/cf/command_registry"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("update-user-provided-service test", func() {
	var (
		ui                  *testterm.FakeUI
		configRepo          core_config.Repository
		serviceRepo         *testapi.FakeUserProvidedServiceInstanceRepository
		requirementsFactory *testreq.FakeReqFactory
		deps                command_registry.Dependency
	)

	updateCommandDependency := func(pluginCall bool) {
		deps.Ui = ui
		deps.RepoLocator = deps.RepoLocator.SetUserProvidedServiceInstanceRepository(serviceRepo)
		deps.Config = configRepo
		command_registry.Commands.SetCommand(command_registry.Commands.FindCommand("update-user-provided-service").SetDependency(deps, pluginCall))
	}

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		serviceRepo = &testapi.FakeUserProvidedServiceInstanceRepository{}
		configRepo = testconfig.NewRepositoryWithDefaults()
		requirementsFactory = &testreq.FakeReqFactory{}
	})

	runCommand := func(args ...string) bool {
		return testcmd.RunCliCommand("update-user-provided-service", args, requirementsFactory, updateCommandDependency, false)
	}

	Describe("requirements", func() {
		It("fails with usage when not provided the name of the service to update", func() {
			requirementsFactory.LoginSuccess = true
			runCommand()
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"Incorrect Usage", "Requires", "argument"},
			))
		})

		It("fails when not logged in", func() {
			Expect(runCommand("whoops")).To(BeFalse())
		})
	})

	Context("when logged in", func() {
		BeforeEach(func() {
			requirementsFactory.LoginSuccess = true

			serviceInstance := models.ServiceInstance{}
			serviceInstance.Name = "service-name"
			requirementsFactory.ServiceInstance = serviceInstance
		})

		Context("when no flags are provided", func() {
			It("tells the user that no changes occurred", func() {
				runCommand("service-name")

				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Updating user provided service", "service-name", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"No changes"},
				))
			})
		})

		Context("when the user provides valid single-quoted JSON with the -p flag", func() {
			It("updates the user provided service specified", func() {
				runCommand("-p", `'{"foo":"bar"}'`, "-l", "syslog://example.com", "service-name")

				Expect(requirementsFactory.ServiceInstanceName).To(Equal("service-name"))
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Updating user provided service", "service-name", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"TIP"},
				))

				Expect(serviceRepo.UpdateArgsForCall(0).Name).To(Equal("service-name"))
				Expect(serviceRepo.UpdateArgsForCall(0).Params).To(Equal(map[string]interface{}{"foo": "bar"}))
				Expect(serviceRepo.UpdateArgsForCall(0).SysLogDrainUrl).To(Equal("syslog://example.com"))
			})
		})

		Context("when the user provides valid double-quoted JSON with the -p flag", func() {
			It("updates the user provided service specified", func() {
				runCommand("-p", `"{"foo":"bar"}"`, "-l", "syslog://example.com", "service-name")

				Expect(requirementsFactory.ServiceInstanceName).To(Equal("service-name"))
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Updating user provided service", "service-name", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"TIP"},
				))

				Expect(serviceRepo.UpdateArgsForCall(0).Name).To(Equal("service-name"))
				Expect(serviceRepo.UpdateArgsForCall(0).Params).To(Equal(map[string]interface{}{"foo": "bar"}))
				Expect(serviceRepo.UpdateArgsForCall(0).SysLogDrainUrl).To(Equal("syslog://example.com"))
			})
		})

		It("accepts service parameters interactively", func() {
			ui.Inputs = []string{"foo value", "bar value", "baz value"}
			runCommand("-p", "foo, bar, baz", "my-custom-service")

			Expect(ui.Prompts).To(ContainSubstrings(
				[]string{"foo"},
				[]string{"bar"},
				[]string{"baz"},
			))

			Expect(serviceRepo.UpdateCallCount()).To(Equal(1))
			serviceInstanceFields := serviceRepo.UpdateArgsForCall(0)
			Expect(serviceInstanceFields.Params).To(Equal(map[string]interface{}{
				"foo": "foo value",
				"bar": "bar value",
				"baz": "baz value",
			}))
		})

		It("accepts service parameters as a file containing JSON without prompting", func() {
			tempfile, err := ioutil.TempFile("", "update-user-provided-service-test")
			Expect(err).NotTo(HaveOccurred())
			ioutil.WriteFile(tempfile.Name(), []byte(`{"foo": "bar"}`), os.ModePerm)

			runCommand("-p", fmt.Sprintf("@%s", tempfile.Name()), "my-custom-service")

			serviceInstanceFields := serviceRepo.UpdateArgsForCall(0)
			Expect(serviceInstanceFields.Params).To(Equal(map[string]interface{}{"foo": "bar"}))

			Expect(ui.Prompts).To(BeEmpty())
		})

		It("fails with an error when given a file containing bad JSON", func() {
			tempfile, err := ioutil.TempFile("", "update-user-provided-service-test")
			Expect(err).NotTo(HaveOccurred())
			jsonData := `{:bad_json:}`
			ioutil.WriteFile(tempfile.Name(), []byte(jsonData), os.ModePerm)

			runCommand("-p", fmt.Sprintf("@%s", tempfile.Name()), "my-custom-service")
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"FAILED"},
			))
		})

		It("fails with an error when given a file that cannot be read", func() {
			runCommand("-p", "@nonexistent-file", "my-custom-service")
			Expect(ui.Outputs).To(ContainSubstrings(
				[]string{"FAILED"},
			))
		})

		Context("when user provides a valid Route Service URL with -r flag", func() {
			It("updates a user provided service with a route service url", func() {
				runCommand("-p", `'{"foo":"bar"}'`, "-r", "https://example.com", "service-name")
				Expect(requirementsFactory.ServiceInstanceName).To(Equal("service-name"))
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"Updating user provided service", "service-name", "my-org", "my-space", "my-user"},
					[]string{"OK"},
					[]string{"TIP"},
				))

				Expect(serviceRepo.UpdateArgsForCall(0).Name).To(Equal("service-name"))
				Expect(serviceRepo.UpdateArgsForCall(0).Params).To(Equal(map[string]interface{}{"foo": "bar"}))
				Expect(serviceRepo.UpdateArgsForCall(0).RouteServiceUrl).To(Equal("https://example.com"))
			})
		})

		Context("when no flags are passed", func() {
			It("warns the user that no changes were made", func() {
				runCommand("service-name")

				Expect(serviceRepo.UpdateCallCount()).To(Equal(1))

				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"No flags specified. No changes were made."},
				))
			})
		})

		Context("when the user provides invalid JSON with the -p flag", func() {
			It("tells the user the JSON is invalid", func() {
				runCommand("-p", `'{"foo":"bar'`, "service-name")

				Expect(serviceRepo.UpdateCallCount()).To(Equal(0))

				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"FAILED"},
					[]string{"JSON is invalid"},
				))
			})
		})

		Context("when the service with the given name is not user provided", func() {
			BeforeEach(func() {
				plan := models.ServicePlanFields{Guid: "my-plan-guid"}
				serviceInstance := models.ServiceInstance{}
				serviceInstance.Name = "found-service-name"
				serviceInstance.ServicePlan = plan

				requirementsFactory.ServiceInstance = serviceInstance
			})

			It("fails and tells the user what went wrong", func() {
				runCommand("-p", `{"foo":"bar"}`, "service-name")

				Expect(serviceRepo.UpdateCallCount()).To(Equal(0))

				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"FAILED"},
					[]string{"Service Instance is not user provided"},
				))
			})
		})
	})
})
