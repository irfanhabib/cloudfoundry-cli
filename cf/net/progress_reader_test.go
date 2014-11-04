package net_test

import (
	"os"

	testterm "github.com/cloudfoundry/cli/testhelpers/terminal"

	. "github.com/cloudfoundry/cli/cf/net"
	. "github.com/cloudfoundry/cli/testhelpers/matchers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = FDescribe("ProgressReader", func() {

	var (
		testFile       *os.File
		err            error
		progressReader *ProgressReader
		ui             *testterm.FakeUI
		b              []byte
	)

	BeforeEach(func() {
		ui = &testterm.FakeUI{}
		testFile, err = os.Open("../../fixtures/test.file")
		Expect(err).ToNot(HaveOccurred())
		fileStat, err := testFile.Stat()
		Expect(err).ToNot(HaveOccurred())

		b = make([]byte, 1024)
		progressReader = NewProgressReader(testFile, ui)
		progressReader.SetTotalSize(fileStat.Size())
	})

	It("prints progress while content is being read", func() {
		for {
			_, err := progressReader.Read(b)
			if err != nil {
				break
			}
		}

		Expect(ui.Outputs).To(ContainSubstrings([]string{"Done uploading"}))

	})
})
