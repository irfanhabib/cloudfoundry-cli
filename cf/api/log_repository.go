package api

import (
	"errors"
	"time"

	. "github.com/cloudfoundry/cli/cf/i18n"

	"github.com/cloudfoundry/cli/cf/api/authentication"
	"github.com/cloudfoundry/cli/cf/configuration/coreconfig"
	consumer "github.com/cloudfoundry/loggregator_consumer"
	"github.com/cloudfoundry/loggregatorlib/logmessage"
	noaa_errors "github.com/cloudfoundry/noaa/errors"
)

//go:generate counterfeiter . LogsRepository

type LogsRepository interface {
	RecentLogsFor(appGUID string) ([]*logmessage.LogMessage, error)
	TailLogsFor(appGUID string, onConnect func()) (<-chan *logmessage.LogMessage, error)
	Close()
}

type LoggregatorLogsRepository struct {
	consumer       consumer.LoggregatorConsumer
	config         coreconfig.Reader
	tokenRefresher authentication.TokenRefresher
	messageQueue   *Loggregator_SortedMessageQueue
}

const bufferTime time.Duration = 25 * time.Millisecond

func NewLoggregatorLogsRepository(config coreconfig.Reader, consumer consumer.LoggregatorConsumer, refresher authentication.TokenRefresher) LogsRepository {
	return &LoggregatorLogsRepository{
		config:         config,
		consumer:       consumer,
		tokenRefresher: refresher,
		messageQueue:   NewLoggregator_SortedMessageQueue(),
	}
}

func (repo *LoggregatorLogsRepository) Close() {
	repo.consumer.Close()
}

func (repo *LoggregatorLogsRepository) RecentLogsFor(appGUID string) ([]*logmessage.LogMessage, error) {
	messages, err := repo.consumer.Recent(appGUID, repo.config.AccessToken())

	switch err.(type) {
	case nil: // do nothing
	case *noaa_errors.UnauthorizedError:
		repo.tokenRefresher.RefreshAuthToken()
		messages, err = repo.consumer.Recent(appGUID, repo.config.AccessToken())
	default:
		return messages, err
	}

	consumer.SortRecent(messages)
	return messages, err
}

func (repo *LoggregatorLogsRepository) TailLogsFor(appGUID string, onConnect func()) (<-chan *logmessage.LogMessage, error) {
	ticker := time.NewTicker(bufferTime)

	c := make(chan *logmessage.LogMessage)

	endpoint := repo.config.LoggregatorEndpoint()
	if endpoint == "" {
		return nil, errors.New(T("Loggregator endpoint missing from config file"))
	}

	repo.consumer.SetOnConnectCallback(onConnect)
	logChan, err := repo.consumer.Tail(appGUID, repo.config.AccessToken())
	switch err.(type) {
	case nil: // do nothing
	case *noaa_errors.UnauthorizedError:
		repo.tokenRefresher.RefreshAuthToken()
		logChan, err = repo.consumer.Tail(appGUID, repo.config.AccessToken())
	default:
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	go func() {
		for _ = range ticker.C {
			repo.flushMessageQueue(c)
		}
	}()

	go func() {
		for msg := range logChan {
			repo.messageQueue.PushMessage(msg)
		}

		repo.flushMessageQueue(c)
		close(c)
	}()

	return c, nil
}

func (repo *LoggregatorLogsRepository) flushMessageQueue(c chan *logmessage.LogMessage) {
	repo.messageQueue.EnumerateAndClear(func(m *logmessage.LogMessage) {
		c <- m
	})
}
