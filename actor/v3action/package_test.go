package v3action_test

import (
	"archive/zip"
	"errors"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	. "code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/actor/v3action/v3actionfakes"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func createFile(root, path, contents string) int64 {
	filepath := filepath.Join(root, path)
	err := ioutil.WriteFile(filepath, []byte(contents), 0666)
	Expect(err).NotTo(HaveOccurred())

	fileInfo, err := os.Stat(filepath)
	Expect(err).NotTo(HaveOccurred())
	return fileInfo.Size()
}

var _ = Describe("Package Actions", func() {
	var (
		actor                     *Actor
		fakeCloudControllerClient *v3actionfakes.FakeCloudControllerClient
		fakeConfig                *v3actionfakes.FakeConfig
	)

	BeforeEach(func() {
		fakeCloudControllerClient = new(v3actionfakes.FakeCloudControllerClient)
		fakeConfig = new(v3actionfakes.FakeConfig)
		actor = NewActor(fakeCloudControllerClient, fakeConfig)
	})

	Describe("CreateAndUploadPackageByApplicationNameAndSpace", func() {
		Context("when the application can be retrieved", func() {
			BeforeEach(func() {
				fakeCloudControllerClient.GetApplicationsReturns(
					[]ccv3.Application{
						{
							Name: "some-app-name",
							GUID: "some-app-guid",
						},
					},
					ccv3.Warnings{"some-app-warning"},
					nil,
				)
			})

			Context("when the zip can be created", func() {
				var (
					bitsPath           string
					expectedFilesInZip map[string]int64
				)

				BeforeEach(func() {
					var err error
					bitsPath, err = ioutil.TempDir("", "example")
					Expect(err).ToNot(HaveOccurred())

					expectedFilesInZip = map[string]int64{
						"tmpfile":         0,
						"folder1/tmpfile": 0,
					}

					err = os.Mkdir(filepath.Join(bitsPath, "folder1"), 0777)
					Expect(err).ToNot(HaveOccurred())

					for path, _ := range expectedFilesInZip {
						expectedFilesInZip[path] = createFile(bitsPath, path, "some-contents")
					}
					expectedFilesInZip["folder1/"] = 0

				})

				AfterEach(func() {
					if bitsPath != "" {
						err := os.RemoveAll(bitsPath)
						Expect(err).ToNot(HaveOccurred())
					}
				})

				Context("when the package is created successfully", func() {
					var createdPackage ccv3.Package

					BeforeEach(func() {
						createdPackage = ccv3.Package{
							GUID:  "some-pkg-guid",
							State: ccv3.PackageStateAwaitingUpload,
							Relationships: ccv3.Relationships{
								ccv3.ApplicationRelationship: ccv3.Relationship{
									GUID: "some-app-guid",
								},
							},
						}

						fakeCloudControllerClient.CreatePackageReturns(
							createdPackage,
							ccv3.Warnings{"some-pkg-warning"},
							nil,
						)
					})

					Context("when the file uploading is successful", func() {
						BeforeEach(func() {
							fakeCloudControllerClient.UploadPackageReturns(ccv3.Package{}, ccv3.Warnings{"some-upload-pkg-warning"}, nil)
						})

						Context("when the polling is successful", func() {
							BeforeEach(func() {
								fakeCloudControllerClient.GetPackageReturns(
									ccv3.Package{GUID: "some-pkg-guid", State: ccv3.PackageStateReady},
									ccv3.Warnings{"some-get-pkg-warning"},
									nil,
								)
							})

							It("correctly constructs the zip", func() {
								fakeCloudControllerClient.UploadPackageStub = func(pkg ccv3.Package, zipFilePart string) (ccv3.Package, ccv3.Warnings, error) {
									filestats := map[string]int64{}
									reader, err := zip.OpenReader(zipFilePart)
									Expect(err).ToNot(HaveOccurred())

									for _, file := range reader.File {
										filestats[file.Name] = file.FileInfo().Size()
									}

									Expect(filestats).To(Equal(expectedFilesInZip))

									return ccv3.Package{}, nil, nil
								}
								_, _, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).NotTo(HaveOccurred())
								Expect(fakeCloudControllerClient.UploadPackageCallCount()).To(Equal(1))
							})

							It("collects all warnings", func() {
								_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).NotTo(HaveOccurred())
								Expect(warnings).To(ConsistOf("some-app-warning", "some-pkg-warning", "some-upload-pkg-warning", "some-get-pkg-warning"))
							})

							It("successfully resolves the app name", func() {
								_, _, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).ToNot(HaveOccurred())

								Expect(fakeCloudControllerClient.GetApplicationsCallCount()).To(Equal(1))
								expectedQuery := url.Values{
									"names":       []string{"some-app-name"},
									"space_guids": []string{"some-space-guid"},
								}
								query := fakeCloudControllerClient.GetApplicationsArgsForCall(0)
								Expect(query).To(Equal(expectedQuery))
							})

							It("successfully creates the Package", func() {
								_, _, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).ToNot(HaveOccurred())

								Expect(fakeCloudControllerClient.CreatePackageCallCount()).To(Equal(1))
								inputPackage := fakeCloudControllerClient.CreatePackageArgsForCall(0)
								Expect(inputPackage).To(Equal(ccv3.Package{
									Type: ccv3.PackageTypeBits,
									Relationships: ccv3.Relationships{
										ccv3.ApplicationRelationship: ccv3.Relationship{GUID: "some-app-guid"},
									},
								}))
							})

							It("returns the package", func() {
								pkg, _, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).ToNot(HaveOccurred())

								expectedPackage := ccv3.Package{
									GUID:  "some-pkg-guid",
									State: ccv3.PackageStateReady,
								}
								Expect(pkg).To(Equal(Package(expectedPackage)))

								Expect(fakeCloudControllerClient.GetPackageCallCount()).To(Equal(1))
								Expect(fakeCloudControllerClient.GetPackageArgsForCall(0)).To(Equal("some-pkg-guid"))
							})

							DescribeTable("polls until terminal state is reached",
								func(finalState ccv3.PackageState, expectedErr error) {
									fakeCloudControllerClient.GetPackageReturns(
										ccv3.Package{GUID: "some-pkg-guid", State: ccv3.PackageStateAwaitingUpload},
										ccv3.Warnings{"some-get-pkg-warning"},
										nil,
									)
									fakeCloudControllerClient.GetPackageReturnsOnCall(
										2,
										ccv3.Package{State: finalState},
										ccv3.Warnings{"some-get-pkg-warning"},
										nil,
									)

									_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)

									if expectedErr == nil {
										Expect(err).ToNot(HaveOccurred())
									} else {
										Expect(err).To(MatchError(expectedErr))
									}

									Expect(warnings).To(ConsistOf("some-app-warning", "some-pkg-warning", "some-upload-pkg-warning", "some-get-pkg-warning", "some-get-pkg-warning", "some-get-pkg-warning"))

									Expect(fakeCloudControllerClient.GetPackageCallCount()).To(Equal(3))
									Expect(fakeConfig.PollingIntervalCallCount()).To(Equal(3))
								},

								Entry("READY", ccv3.PackageStateReady, nil),
								Entry("FAILED", ccv3.PackageStateFailed, PackageProcessingFailedError{}),
								Entry("EXPIRED", ccv3.PackageStateExpired, PackageProcessingExpiredError{}),
							)
						})

						Context("when the polling errors", func() {
							var expectedErr error
							BeforeEach(func() {
								expectedErr = errors.New("Fake error during polling")
								fakeCloudControllerClient.GetPackageReturns(
									ccv3.Package{},
									ccv3.Warnings{"some-get-pkg-warning"},
									expectedErr,
								)
							})

							It("returns the error and warnings", func() {
								_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
								Expect(err).To(MatchError(expectedErr))
								Expect(warnings).To(ConsistOf("some-app-warning", "some-pkg-warning", "some-upload-pkg-warning", "some-get-pkg-warning"))
							})
						})
					})

					Context("when the file uploading errors", func() {
						var expectedErr error

						BeforeEach(func() {
							expectedErr = errors.New("ZOMG Package Uploading")
							fakeCloudControllerClient.UploadPackageReturns(ccv3.Package{}, ccv3.Warnings{"some-upload-pkg-warning"}, expectedErr)
						})

						It("returns the warnings and the error", func() {
							_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
							Expect(err).To(MatchError(expectedErr))
							Expect(warnings).To(ConsistOf("some-app-warning", "some-pkg-warning", "some-upload-pkg-warning"))
						})
					})
				})

				Context("when the package creation errors", func() {
					var expectedErr error

					BeforeEach(func() {
						expectedErr = errors.New("ZOMG Package Creation")
						fakeCloudControllerClient.CreatePackageReturns(
							ccv3.Package{},
							ccv3.Warnings{"some-pkg-warning"},
							expectedErr,
						)
					})

					It("returns the warnings and the error", func() {
						_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", bitsPath)
						Expect(err).To(MatchError(expectedErr))
						Expect(warnings).To(ConsistOf("some-app-warning", "some-pkg-warning"))
					})
				})
			})

			Context("when creating the zip errors", func() {
				It("returns the warnings and the error", func() {
					_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", "/banana")
					// Windows returns back a different error message
					Expect(err.Error()).To(MatchRegexp("open /banana: no such file or directory|The system cannot find the file specified"))
					Expect(warnings).To(ConsistOf("some-app-warning"))
				})
			})
		})

		Context("when retrieving the application errors", func() {
			var expectedErr error

			BeforeEach(func() {
				expectedErr = errors.New("I am a CloudControllerClient Error")
				fakeCloudControllerClient.GetApplicationsReturns(
					[]ccv3.Application{},
					ccv3.Warnings{"some-warning"},
					expectedErr)
			})

			It("returns the warnings and the error", func() {
				_, warnings, err := actor.CreateAndUploadPackageByApplicationNameAndSpace("some-app-name", "some-space-guid", "some-path")
				Expect(err).To(MatchError(expectedErr))
				Expect(warnings).To(ConsistOf("some-warning"))
			})
		})
	})
})
