package ui_test

import (
	"code.cloudfoundry.org/cli/util/configv3"
	. "code.cloudfoundry.org/cli/util/ui"
	"code.cloudfoundry.org/cli/util/ui/uifakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
)

var _ = Describe("UI", func() {
	var (
		ui         *UI
		fakeConfig *uifakes.FakeConfig
		out        *Buffer
	)

	BeforeEach(func() {
		fakeConfig = new(uifakes.FakeConfig)
		fakeConfig.ColorEnabledReturns(configv3.ColorEnabled)
	})

	JustBeforeEach(func() {
		var err error
		ui, err = NewUI(fakeConfig)
		Expect(err).NotTo(HaveOccurred())

		out = NewBuffer()
		ui.Out = out
		ui.Err = NewBuffer()
	})

	Describe("DisplayChangeForPush", func() {
		Context("in english", func() {
			Context("when passed strings for values", func() {
				Context("when the values are not equal", func() {
					Context("when the originalValue is not empty", func() {
						It("should display the header with differences", func() {
							err := ui.DisplayChangeForPush("val", 2, "old", "new")
							Expect(err).ToNot(HaveOccurred())
							Expect(out).To(Say("\x1b\\[31m\\-\\s+val  old\x1b\\[0m"))
							Expect(out).To(Say("\x1b\\[32m\\+\\s+val  new\x1b\\[0m"))
						})
					})

					Context("when the originalValue is empty", func() {
						It("should display the header with the new value only", func() {
							err := ui.DisplayChangeForPush("val", 2, "", "new")
							Expect(err).ToNot(HaveOccurred())
							Expect(out).To(Say("\x1b\\[32m\\+\\s+val  new\x1b\\[0m"))

							err = ui.DisplayChangeForPush("val", 2, "", "new")
							Expect(err).ToNot(HaveOccurred())
							Expect(out).ToNot(Say("\x1b\\[31m\\-\\s+val  old\x1b\\[0m"))
						})
					})
				})

				Context("when the values are the equal", func() {
					It("should display the header without differences", func() {
						err := ui.DisplayChangeForPush("val", 2, "old", "old")
						Expect(err).ToNot(HaveOccurred())
						Expect(out).To(Say("(?m)^\\s+val  old$"))
					})
				})

				Context("when the values are a different type", func() {
					It("should return an ErrValueMissmatch", func() {
						err := ui.DisplayChangeForPush("asdf", 2, "asdf", 7)
						Expect(err).To(MatchError(ErrValueMissmatch))
					})
				})
			})

			Context("when passed list of strings for values", func() {
				It("should display the header with sorted differences", func() {
					old := []string{"route2", "route1", "route4"}
					new := []string{"route4", "route2", "route3"}
					err := ui.DisplayChangeForPush("val", 2, old, new)
					Expect(err).ToNot(HaveOccurred())
					Expect(out).To(Say("\\s+val"))
					Expect(out).To(Say("\x1b\\[31m\\-\\s+route1\x1b\\[0m"))
					Expect(out).To(Say("(?m)^\\s+route2$"))
					Expect(out).To(Say("\x1b\\[32m\\+\\s+route3\x1b\\[0m"))
					Expect(out).To(Say("(?m)^\\s+route4$"))
				})

				Context("when the values are a different type", func() {
					It("should return an ErrValueMissmatch", func() {
						err := ui.DisplayChangeForPush("asdf", 2, []string{"route4", "route2", "route3"}, 7)
						Expect(err).To(MatchError(ErrValueMissmatch))
					})
				})
			})
		})

		Context("in a non-english language", func() {
			BeforeEach(func() {
				fakeConfig.LocaleReturns("fr-FR")
			})

			Context("when passed strings for values", func() {
				Context("when the values are not equal", func() {
					It("should display the differences", func() {
						err := ui.DisplayChangeForPush("Name", 2, "old", "new")
						Expect(err).ToNot(HaveOccurred())
						Expect(out).To(Say("\x1b\\[31m\\-\\s+Nom  old\x1b\\[0m"))
						Expect(out).To(Say("\x1b\\[32m\\+\\s+Nom  new\x1b\\[0m"))
					})
				})

				Context("when the values are the equal", func() {
					It("should display the header without differences", func() {
						err := ui.DisplayChangeForPush("Name", 2, "old", "old")
						Expect(err).ToNot(HaveOccurred())
						Expect(out).To(Say("(?m)^\\s+Nom  old$"))
					})
				})
			})

			Context("when passed list of strings for values", func() {
				It("should display the header with sorted differences", func() {
					old := []string{"route2", "route1", "route4"}
					new := []string{"route4", "route2", "route3"}
					err := ui.DisplayChangeForPush("Name", 2, old, new)
					Expect(err).ToNot(HaveOccurred())
					Expect(out).To(Say("\\s+Nom"))
					Expect(out).To(Say("\x1b\\[31m\\-\\s+route1\x1b\\[0m"))
					Expect(out).To(Say("(?m)^\\s+route2$"))
					Expect(out).To(Say("\x1b\\[32m\\+\\s+route3\x1b\\[0m"))
					Expect(out).To(Say("(?m)^\\s+route4$"))
				})
			})
		})
	})

	Describe("DisplayChangesForPush", func() {
		It("alings all the string types", func() {
			changeSet := []Change{
				{
					Header:       "h1",
					CurrentValue: "old",
					NewValue:     "new",
				},
				{
					Header:       "header2",
					CurrentValue: "old",
					NewValue:     "old",
				},
				{
					Header:       "header3",
					CurrentValue: []string{"route2", "route1", "route4"},
					NewValue:     []string{"route4", "route2", "route3"},
				},
			}

			err := ui.DisplayChangesForPush(changeSet)
			Expect(err).ToNot(HaveOccurred())

			Expect(out).To(Say("\x1b\\[31m\\-\\s+h1        old\x1b\\[0m"))
			Expect(out).To(Say("\x1b\\[32m\\+\\s+h1        new\x1b\\[0m"))
			Expect(out).To(Say("(?m)^\\s+header2   old"))
			Expect(out).To(Say("(?m)^\\s+header3$"))
			Expect(out).To(Say("\x1b\\[31m\\-\\s+route1\x1b\\[0m"))
			Expect(out).To(Say("(?m)^\\s+route2$"))
			Expect(out).To(Say("\x1b\\[32m\\+\\s+route3\x1b\\[0m"))
			Expect(out).To(Say("(?m)^\\s+route4$"))
		})
	})
})
