// +build windows

package i18n_test

import (
	"os"
	"path/filepath"

	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/i18n"
	testconfig "github.com/cloudfoundry/cli/testhelpers/configuration"
	"github.com/pivotal-cf-experimental/jibber_jabber"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("i18n.Init() function", func() {
	var (
		configRepo core_config.ReadWriter
	)

	BeforeEach(func() {
		i18n.Resources_path = filepath.Join("cf", "i18n", "test_fixtures")
		configRepo = testconfig.NewRepositoryWithDefaults()
	})

	Describe("When a user has a locale configuration set", func() {
		Context("creates a valid T function", func() {
			BeforeEach(func() {
				configRepo.SetLocale("en_US")
			})

			It("returns a usable T function for simple strings", func() {
				T := i18n.Init(configRepo)
				Ω(T).ShouldNot(BeNil())

				translation := T("Hello world!")
				Ω("Hello world!").Should(Equal(translation))
			})

			It("returns a usable T function for complex strings (interpolated)", func() {
				T := i18n.Init(configRepo)
				Ω(T).ShouldNot(BeNil())

				translation := T("Deleting domain {{.DomainName}} as {{.Username}}...", map[string]interface{}{"DomainName": "foo.com", "Username": "Anand"})
				Ω("Deleting domain foo.com as Anand...").Should(Equal(translation))
			})
		})
	})

	Describe("When a user does not have a locale configuration set", func() {
		BeforeEach(func() {
			os.Setenv("LC_ALL", "en_US.UTF-8")

			//All these tests require the system language to be English
			Ω(jibber_jabber.DetectIETF()).Should(Equal("en-US"))
		})

		Context("creates a valid T function", func() {
			It("returns a usable T function for simple strings", func() {
				T := i18n.Init(configRepo)
				Ω(T).ShouldNot(BeNil())

				translation := T("Change user password")
				Ω("Change user password").Should(Equal(translation))
			})

			It("returns a usable T function for complex strings (interpolated)", func() {
				T := i18n.Init(configRepo)
				Ω(T).ShouldNot(BeNil())

				translation := T("Deleting domain {{.DomainName}} as {{.Username}}...", map[string]interface{}{"DomainName": "foo", "Username": "Anand"})
				Ω("Deleting domain foo as Anand...").Should(Equal(translation))
			})
		})

	})

	Describe("When locale is HK/TW", func() {
		It("matches zh_CN to zh_Hans", func() {
			os.Setenv("LC_ALL", "zh_CN.UTF-8")
			T := i18n.Init(configRepo)
			Ω(T).ShouldNot(BeNil())

			translation := T("No buildpacks found")
			Ω("buildpack未找到").Should(Equal(translation))
		})

		It("matches zh_TW to zh_Hant", func() {
			os.Setenv("LC_ALL", "zh_TW.UTF-8")
			T := i18n.Init(configRepo)
			Ω(T).ShouldNot(BeNil())

			translation := T("No buildpacks found")
			Ω("(Hant)No buildpacks found").Should(Equal(translation))
		})

		It("matches zh_HK to zh_Hant", func() {
			os.Setenv("LC_ALL", "zh_HK.UTF-8")
			T := i18n.Init(configRepo)
			Ω(T).ShouldNot(BeNil())

			translation := T("No buildpacks found")
			Ω("(Hant)No buildpacks found").Should(Equal(translation))
		})
	})
})
