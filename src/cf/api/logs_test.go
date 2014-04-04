package api_test

import (
	. "cf/api"
	"cf/configuration"
	"cf/errors"
	"code.google.com/p/gogoprotobuf/proto"
	"github.com/cloudfoundry/loggregatorlib/logmessage"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	testapi "testhelpers/api"
	testconfig "testhelpers/configuration"
	"time"
)

var _ = Describe("loggregator logs repository", func() {
	var (
		fakeConsumer *testapi.FakeLoggregatorConsumer
		logsRepo     *LoggregatorLogsRepository
		configRepo   configuration.ReadWriter
	)

	BeforeEach(func() {
		fakeConsumer = testapi.NewFakeLoggregatorConsumer()
		configRepo = testconfig.NewRepositoryWithDefaults()
		configRepo.SetLoggregatorEndpoint("loggregator-server.test.com")
		configRepo.SetAccessToken("the-access-token")
		repo := NewLoggregatorLogsRepository(configRepo, fakeConsumer)
		logsRepo = &repo
	})

	Describe("RecentLogsFor", func() {
		Context("when an error occurs", func() {
			BeforeEach(func() {
				fakeConsumer.RecentReturns.Err = errors.New("oops")
			})

			It("returns the error", func() {
				_, err := logsRepo.RecentLogsFor("app-guid")
				Expect(err).To(Equal(errors.New("oops")))
			})
		})

		Context("when an error does not occur", func() {
			BeforeEach(func() {
				fakeConsumer.RecentReturns.Messages = []*logmessage.LogMessage{
					makeLogMessage("My message 2", int64(2000)),
					makeLogMessage("My message 1", int64(1000)),
				}
			})

			It("gets the logs for the requested app", func() {
				logsRepo.RecentLogsFor("app-guid")
				Expect(fakeConsumer.RecentCalledWith.AppGuid).To(Equal("app-guid"))
			})

			It("writes the sorted log messages onto the provided channel", func() {
				messages, err := logsRepo.RecentLogsFor("app-guid")
				Expect(err).NotTo(HaveOccurred())

				Expect(string(messages[0].Message)).To(Equal("My message 1"))
				Expect(string(messages[1].Message)).To(Equal("My message 2"))
			})
		})
	})

	Describe("tailing logs", func() {
		Context("when an error occurs", func() {
			BeforeEach(func() {
				fakeConsumer.TailFunc = func(_, _ string) (<-chan *logmessage.LogMessage, error) {
					return nil, errors.New("oops")
				}
			})

			It("returns an error", func() {
				err := logsRepo.TailLogsFor("app-guid", 1*time.Millisecond, func() {}, func(*logmessage.LogMessage) {

				})
				Expect(err).To(Equal(errors.New("oops")))
			})
		})

		Context("when no error occurs", func() {
			It("asks for the logs for the given app", func(done Done) {
				fakeConsumer.TailFunc = func(appGuid, token string) (<-chan *logmessage.LogMessage, error) {
					Expect(appGuid).To(Equal("app-guid"))
					Expect(token).To(Equal("the-access-token"))
					close(done)
					return nil, nil
				}

				logsRepo.TailLogsFor("app-guid", 1*time.Millisecond, func() {}, func(msg *logmessage.LogMessage) {})
			})

			It("sets the on connect callback", func(done Done) {
				fakeConsumer.TailFunc = func(_, _ string) (<-chan *logmessage.LogMessage, error) {
					close(done)
					return nil, nil
				}

				called := false
				logsRepo.TailLogsFor("app-guid", 1*time.Millisecond, func() { called = true }, func(msg *logmessage.LogMessage) {})
				fakeConsumer.OnConnectCallback()
				Expect(called).To(BeTrue())
			})

			It("sorts the messages before yielding them", func(done Done) {
				fakeConsumer.TailFunc = func(_, _ string) (<-chan *logmessage.LogMessage, error) {
					logChan := make(chan *logmessage.LogMessage)
					go func() {
						logChan <- makeLogMessage("hello3", 300)
						logChan <- makeLogMessage("hello2", 200)
						logChan <- makeLogMessage("hello1", 100)
						fakeConsumer.WaitForClose()
						close(logChan)
					}()

					return logChan, nil
				}

				receivedMessages := []*logmessage.LogMessage{}
				err := logsRepo.TailLogsFor("app-guid", 10*time.Millisecond, func() {}, func(msg *logmessage.LogMessage) {
					receivedMessages = append(receivedMessages, msg)
					if len(receivedMessages) >= 3 {
						logsRepo.Close()
					}
				})

				Expect(err).NotTo(HaveOccurred())

				Expect(receivedMessages).To(Equal([]*logmessage.LogMessage{
					makeLogMessage("hello1", 100),
					makeLogMessage("hello2", 200),
					makeLogMessage("hello3", 300),
				}))

				close(done)
			})
		})
	})
})

func makeLogMessage(message string, timestamp int64) *logmessage.LogMessage {
	messageType := logmessage.LogMessage_OUT
	sourceName := "DEA"
	return &logmessage.LogMessage{
		Message:     []byte(message),
		AppId:       proto.String("my-app-guid"),
		MessageType: &messageType,
		SourceName:  &sourceName,
		Timestamp:   proto.Int64(timestamp),
	}

}
