package commands_test

import (
	"errors"

	"github.com/cloudfoundry/cli/cf/command_registry"
	"github.com/cloudfoundry/cli/cf/commands"
	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/models"
	"github.com/cloudfoundry/cli/cf/requirements"
	"github.com/cloudfoundry/cli/flags"

	testapi "github.com/cloudfoundry/cli/cf/api/fakes"
	testManifest "github.com/cloudfoundry/cli/cf/manifest/fakes"
	fakerequirements "github.com/cloudfoundry/cli/cf/requirements/fakes"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	. "github.com/cloudfoundry/cli/testhelpers/matchers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CreateAppManifest", func() {
	var (
		ui             *testterm.FakeUI
		configRepo     core_config.Repository
		appSummaryRepo *testapi.FakeAppSummaryRepository

		cmd         command_registry.Command
		deps        command_registry.Dependency
		factory     *fakerequirements.FakeFactory
		flagContext flags.FlagContext

		loginRequirement         requirements.Requirement
		targetedSpaceRequirement requirements.Requirement
		applicationRequirement   *fakerequirements.FakeApplicationRequirement

		fakeManifest *testManifest.FakeAppManifest
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		configRepo = testconfig.NewRepositoryWithDefaults()
		appSummaryRepo = &testapi.FakeAppSummaryRepository{}
		repoLocator := deps.RepoLocator.SetAppSummaryRepository(appSummaryRepo)

		fakeManifest = &testManifest.FakeAppManifest{}

		deps = command_registry.Dependency{
			Ui:          ui,
			Config:      configRepo,
			RepoLocator: repoLocator,
			AppManifest: fakeManifest,
		}

		cmd = &commands.CreateAppManifest{}
		cmd.SetDependency(deps, false)

		flagContext = flags.NewFlagContext(cmd.MetaData().Flags)
		factory = &fakerequirements.FakeFactory{}

		loginRequirement = &passingRequirement{Name: "login-requirement"}
		factory.NewLoginRequirementReturns(loginRequirement)

		targetedSpaceRequirement = &passingRequirement{Name: "targeted-space-requirement"}
		factory.NewTargetedSpaceRequirementReturns(targetedSpaceRequirement)

		applicationRequirement = &fakerequirements.FakeApplicationRequirement{}
		application := models.Application{}
		application.Guid = "app-guid"
		applicationRequirement.GetApplicationReturns(application)
		factory.NewApplicationRequirementReturns(applicationRequirement)
	})

	Describe("Requirements", func() {
		Context("when not provided exactly one arg", func() {
			BeforeEach(func() {
				flagContext.Parse("app-name", "extra-arg")
			})

			It("fails with usage", func() {
				Expect(func() { cmd.Requirements(factory, flagContext) }).To(Panic())
				Expect(ui.Outputs).To(ContainSubstrings(
					[]string{"FAILED"},
					[]string{"Incorrect Usage. Requires APP_NAME as argument"},
				))
			})
		})

		Context("when provided exactly one arg", func() {
			BeforeEach(func() {
				flagContext.Parse("app-name")
			})

			It("returns a LoginRequirement", func() {
				actualRequirements, err := cmd.Requirements(factory, flagContext)
				Expect(err).NotTo(HaveOccurred())
				Expect(actualRequirements).To(ContainElement(loginRequirement))
			})

			It("returns an ApplicationRequirement", func() {
				actualRequirements, err := cmd.Requirements(factory, flagContext)
				Expect(err).NotTo(HaveOccurred())
				Expect(actualRequirements).To(ContainElement(applicationRequirement))
			})

			It("returns a TargetedSpaceRequirement", func() {
				actualRequirements, err := cmd.Requirements(factory, flagContext)
				Expect(err).NotTo(HaveOccurred())
				Expect(actualRequirements).To(ContainElement(targetedSpaceRequirement))
			})
		})
	})

	Describe("Execute", func() {
		BeforeEach(func() {
			err := flagContext.Parse("app-name")
			Expect(err).NotTo(HaveOccurred())
			_, err = cmd.Requirements(factory, flagContext)
			Expect(err).NotTo(HaveOccurred())
		})

		It("tries to get the app summary", func() {
			cmd.Execute(flagContext)
			Expect(appSummaryRepo.GetSummaryCallCount()).To(Equal(1))
		})

		Context("when there is an error getting the app summary", func() {
			BeforeEach(func() {
				appSummaryRepo.GetSummaryReturns(models.Application{}, errors.New("get-summary-err"))
			})
		})

		Context("when getting the app summary succeeds", func() {
			var application models.Application

			BeforeEach(func() {
				application = models.Application{}
				application.Name = "app-name"
				application.Memory = 1024
				application.InstanceCount = 2
			})

			JustBeforeEach(func() {
				appSummaryRepo.GetSummaryReturns(application, nil)
			})

			It("sets the save path", func() {
				cmd.Execute(flagContext)
				Expect(fakeManifest.FileSavePathCallCount()).To(Equal(1))
				Expect(fakeManifest.FileSavePathArgsForCall(0)).To(Equal("./app-name_manifest.yml"))
			})

			Context("when a save path is provided", func() {
				BeforeEach(func() {
					err := flagContext.Parse("app-name", "-p", "save-path")
					Expect(err).NotTo(HaveOccurred())
				})

				It("sets the save path to the provided path", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.FileSavePathCallCount()).To(Equal(1))
					Expect(fakeManifest.FileSavePathArgsForCall(0)).To(Equal("save-path"))
				})
			})

			It("sets memory", func() {
				cmd.Execute(flagContext)
				Expect(fakeManifest.MemoryCallCount()).To(Equal(1))
				name, memory := fakeManifest.MemoryArgsForCall(0)
				Expect(name).To(Equal("app-name"))
				Expect(memory).To(Equal(int64(1024)))
			})

			It("sets instances", func() {
				cmd.Execute(flagContext)
				Expect(fakeManifest.InstancesCallCount()).To(Equal(1))
				name, instances := fakeManifest.InstancesArgsForCall(0)
				Expect(name).To(Equal("app-name"))
				Expect(instances).To(Equal(2))
			})

			It("tries to save the manifest", func() {
				cmd.Execute(flagContext)
				Expect(fakeManifest.SaveCallCount()).To(Equal(1))
			})

			Context("when saving the manifest succeeds", func() {
				BeforeEach(func() {
					fakeManifest.SaveReturns(nil)
				})

				It("says OK", func() {
					cmd.Execute(flagContext)
					Expect(ui.Outputs).To(ContainSubstrings(
						[]string{"OK"},
						[]string{"Manifest file created successfully at ./app-name_manifest.yml"},
					))
				})
			})

			Context("when saving the manifest fails", func() {
				BeforeEach(func() {
					fakeManifest.SaveReturns(errors.New("save-err"))
				})

				It("fails with error", func() {
					Expect(func() { cmd.Execute(flagContext) }).To(Panic())
					Expect(ui.Outputs).To(ContainSubstrings(
						[]string{"FAILED"},
						[]string{"Error creating manifest file: save-err"},
					))
				})
			})

			Context("when the app has a command", func() {
				BeforeEach(func() {
					application.Command = "app-command"
				})

				It("sets the start command", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.StartCommandCallCount()).To(Equal(1))
					name, command := fakeManifest.StartCommandArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(command).To(Equal("app-command"))
				})
			})

			Context("when the app has a buildpack", func() {
				BeforeEach(func() {
					application.BuildpackUrl = "buildpack"
				})

				It("sets the buildpack", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.BuildpackUrlCallCount()).To(Equal(1))
					name, buildpack := fakeManifest.BuildpackUrlArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(buildpack).To(Equal("buildpack"))
				})
			})

			Context("when the app has services", func() {
				BeforeEach(func() {
					application.Services = []models.ServicePlanSummary{
						{
							Name: "sp1-name",
						},
						{
							Name: "sp2-name",
						},
					}
				})

				It("sets the services", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.ServiceCallCount()).To(Equal(2))

					name, service := fakeManifest.ServiceArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(service).To(Equal("sp1-name"))

					name, service = fakeManifest.ServiceArgsForCall(1)
					Expect(name).To(Equal("app-name"))
					Expect(service).To(Equal("sp2-name"))
				})
			})

			Context("when the app has a health check timeout", func() {
				BeforeEach(func() {
					application.HealthCheckTimeout = 5
				})

				It("sets the health check timeout", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.HealthCheckTimeoutCallCount()).To(Equal(1))
					name, timeout := fakeManifest.HealthCheckTimeoutArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(timeout).To(Equal(5))
				})
			})

			Context("when the app has environment vars", func() {
				BeforeEach(func() {
					application.EnvironmentVars = map[string]interface{}{
						"float64-key": float64(5),
						"bool-key":    true,
						"string-key":  "string",
					}
				})

				It("sets the env vars", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.EnvironmentVarsCallCount()).To(Equal(3))
					actuals := map[string]interface{}{}

					for i := 0; i < 3; i++ {
						name, k, v := fakeManifest.EnvironmentVarsArgsForCall(i)
						Expect(name).To(Equal("app-name"))
						actuals[k] = v
					}

					Expect(actuals["float64-key"]).To(Equal("5"))
					Expect(actuals["bool-key"]).To(Equal("true"))
					Expect(actuals["string-key"]).To(Equal(`"string"`))
				})
			})

			Context("when the app has an environment var of an unsupported type", func() {
				BeforeEach(func() {
					application.EnvironmentVars = map[string]interface{}{
						"key": int(1),
					}
				})

				It("fails with error", func() {
					Expect(func() { cmd.Execute(flagContext) }).To(Panic())
					Expect(ui.Outputs).To(ContainSubstrings(
						[]string{"FAILED"},
						[]string{"Failed to create manifest, unable to parse environment variable: key"},
					))
				})
			})

			Context("when the app has routes", func() {
				BeforeEach(func() {
					application.Routes = []models.RouteSummary{
						{
							Host: "route-1-host",
							Domain: models.DomainFields{
								Name: "domain-1-name",
							},
						},
						{
							Host: "route-2-host",
							Domain: models.DomainFields{
								Name: "domain-2-name",
							},
						},
					}
				})

				It("sets the domains", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.DomainCallCount()).To(Equal(2))

					name, host, domainName := fakeManifest.DomainArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(host).To(Equal("route-1-host"))
					Expect(domainName).To(Equal("domain-1-name"))

					name, host, domainName = fakeManifest.DomainArgsForCall(1)
					Expect(name).To(Equal("app-name"))
					Expect(host).To(Equal("route-2-host"))
					Expect(domainName).To(Equal("domain-2-name"))
				})
			})

			Context("when the app has a disk quota", func() {
				BeforeEach(func() {
					application.DiskQuota = 1024
				})

				It("sets the disk quota", func() {
					cmd.Execute(flagContext)
					Expect(fakeManifest.DiskQuotaCallCount()).To(Equal(1))
					name, quota := fakeManifest.DiskQuotaArgsForCall(0)
					Expect(name).To(Equal("app-name"))
					Expect(quota).To(Equal(int64(1024)))
				})
			})
		})
	})
})
