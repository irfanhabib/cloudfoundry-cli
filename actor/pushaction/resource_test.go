package pushaction_test

import (
	"errors"
	"io/ioutil"
	"os"

	. "code.cloudfoundry.org/cli/actor/pushaction"
	"code.cloudfoundry.org/cli/actor/pushaction/pushactionfakes"
	"code.cloudfoundry.org/cli/actor/v2action"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resources", func() {
	var (
		actor       *Actor
		fakeV2Actor *pushactionfakes.FakeV2Actor
	)

	BeforeEach(func() {
		fakeV2Actor = new(pushactionfakes.FakeV2Actor)
		actor = NewActor(fakeV2Actor)
	})

	Describe("CreateArchive", func() {
		var (
			config ApplicationConfig

			archivePath string
			executeErr  error

			resourcesToArchive []v2action.Resource
		)

		BeforeEach(func() {
			config = ApplicationConfig{
				Path: "some-path",
				DesiredApplication: v2action.Application{
					GUID: "some-app-guid",
				},
			}

			resourcesToArchive = []v2action.Resource{{Filename: "file1"}, {Filename: "file2"}}
			config.AllResources = resourcesToArchive
		})

		JustBeforeEach(func() {
			archivePath, executeErr = actor.CreateArchive(config)
		})

		Context("when the zipping is successful", func() {
			var fakeArchivePath string
			BeforeEach(func() {
				fakeArchivePath = "some-archive-path"
				fakeV2Actor.ZipResourcesReturns(fakeArchivePath, nil)
			})

			It("returns the path to the zip", func() {
				Expect(executeErr).ToNot(HaveOccurred())
				Expect(archivePath).To(Equal(fakeArchivePath))

				Expect(fakeV2Actor.ZipResourcesCallCount()).To(Equal(1))
				sourceDir, passedResources := fakeV2Actor.ZipResourcesArgsForCall(0)
				Expect(sourceDir).To(Equal("some-path"))
				Expect(passedResources).To(Equal(resourcesToArchive))
			})
		})

		Context("when creating the archive errors", func() {
			var expectedErr error

			BeforeEach(func() {
				expectedErr = errors.New("oh no")
				fakeV2Actor.ZipResourcesReturns("", expectedErr)
			})

			It("sends errors and returns true", func() {
				Expect(executeErr).To(MatchError(expectedErr))
			})
		})
	})

	Describe("UploadPackage", func() {
		var (
			config      ApplicationConfig
			archivePath string
			eventStream chan Event

			warnings   Warnings
			executeErr error
		)

		BeforeEach(func() {
			config = ApplicationConfig{
				DesiredApplication: v2action.Application{
					GUID: "some-app-guid",
				},
			}
			eventStream = make(chan Event)
		})

		AfterEach(func() {
			close(eventStream)
		})

		JustBeforeEach(func() {
			warnings, executeErr = actor.UploadPackage(config, archivePath, eventStream)
		})

		Context("when the archive can be accessed properly", func() {
			BeforeEach(func() {
				tmpfile, err := ioutil.TempFile("", "fake-archive")
				Expect(err).ToNot(HaveOccurred())
				_, err = tmpfile.Write([]byte("123456"))
				Expect(err).ToNot(HaveOccurred())
				Expect(tmpfile.Close()).ToNot(HaveOccurred())

				archivePath = tmpfile.Name()
			})

			AfterEach(func() {
				if archivePath != "" {
					os.Remove(archivePath)
				}
			})

			Context("when the upload is successful", func() {
				BeforeEach(func() {
					fakeV2Actor.UploadApplicationPackageReturns(v2action.Warnings{"upload-warning-1", "upload-warning-2"}, nil)

					go func() {
						defer GinkgoRecover()

						Eventually(eventStream).Should(Receive(Equal(UploadingApplication)))
						Eventually(eventStream).Should(Receive(Equal(UploadComplete)))
					}()
				})

				It("returns the warnings", func() {
					Expect(executeErr).ToNot(HaveOccurred())
					Expect(warnings).To(ConsistOf("upload-warning-1", "upload-warning-2"))

					Expect(fakeV2Actor.UploadApplicationPackageCallCount()).To(Equal(1))
					appGUID, existingResources, _, newResourcesLength := fakeV2Actor.UploadApplicationPackageArgsForCall(0)
					Expect(appGUID).To(Equal("some-app-guid"))
					Expect(existingResources).To(BeEmpty())
					Expect(newResourcesLength).To(BeNumerically("==", 6))
				})
			})

			Context("when the upload errors", func() {
				var expectedErr error

				BeforeEach(func() {
					expectedErr = errors.New("I can't let you do that starfox")
					fakeV2Actor.UploadApplicationPackageReturns(v2action.Warnings{"upload-warning-1", "upload-warning-2"}, expectedErr)

					go func() {
						defer GinkgoRecover()

						Eventually(eventStream).Should(Receive(Equal(UploadingApplication)))
						Consistently(eventStream).ShouldNot(Receive())
					}()
				})

				It("returns the error and warnings", func() {
					Expect(executeErr).To(MatchError(expectedErr))
					Expect(warnings).To(ConsistOf("upload-warning-1", "upload-warning-2"))
				})
			})
		})

		Context("when the archive returns any access errors", func() {
			It("returns the error", func() {
				Expect(executeErr).To(MatchError(ContainSubstring("no such file or directory")))
			})
		})
	})
})
