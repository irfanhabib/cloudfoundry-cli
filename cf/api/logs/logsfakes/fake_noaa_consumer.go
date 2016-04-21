// This file was generated by counterfeiter
package logsfakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/api/logs"
	"github.com/cloudfoundry/sonde-go/events"
)

type FakeNoaaConsumer struct {
	TailingLogsStub        func(string, string) (<-chan *events.LogMessage, <-chan error)
	tailingLogsMutex       sync.RWMutex
	tailingLogsArgsForCall []struct {
		arg1 string
		arg2 string
	}
	tailingLogsReturns struct {
		result1 <-chan *events.LogMessage
		result2 <-chan error
	}
	RecentLogsStub        func(appGuid string, authToken string) ([]*events.LogMessage, error)
	recentLogsMutex       sync.RWMutex
	recentLogsArgsForCall []struct {
		appGuid   string
		authToken string
	}
	recentLogsReturns struct {
		result1 []*events.LogMessage
		result2 error
	}
	CloseStub        func() error
	closeMutex       sync.RWMutex
	closeArgsForCall []struct{}
	closeReturns     struct {
		result1 error
	}
	SetOnConnectCallbackStub        func(cb func())
	setOnConnectCallbackMutex       sync.RWMutex
	setOnConnectCallbackArgsForCall []struct {
		cb func()
	}
}

func (fake *FakeNoaaConsumer) TailingLogs(arg1 string, arg2 string) (<-chan *events.LogMessage, <-chan error) {
	fake.tailingLogsMutex.Lock()
	fake.tailingLogsArgsForCall = append(fake.tailingLogsArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.tailingLogsMutex.Unlock()
	if fake.TailingLogsStub != nil {
		return fake.TailingLogsStub(arg1, arg2)
	} else {
		return fake.tailingLogsReturns.result1, fake.tailingLogsReturns.result2
	}
}

func (fake *FakeNoaaConsumer) TailingLogsCallCount() int {
	fake.tailingLogsMutex.RLock()
	defer fake.tailingLogsMutex.RUnlock()
	return len(fake.tailingLogsArgsForCall)
}

func (fake *FakeNoaaConsumer) TailingLogsArgsForCall(i int) (string, string) {
	fake.tailingLogsMutex.RLock()
	defer fake.tailingLogsMutex.RUnlock()
	return fake.tailingLogsArgsForCall[i].arg1, fake.tailingLogsArgsForCall[i].arg2
}

func (fake *FakeNoaaConsumer) TailingLogsReturns(result1 <-chan *events.LogMessage, result2 <-chan error) {
	fake.TailingLogsStub = nil
	fake.tailingLogsReturns = struct {
		result1 <-chan *events.LogMessage
		result2 <-chan error
	}{result1, result2}
}

func (fake *FakeNoaaConsumer) RecentLogs(appGuid string, authToken string) ([]*events.LogMessage, error) {
	fake.recentLogsMutex.Lock()
	fake.recentLogsArgsForCall = append(fake.recentLogsArgsForCall, struct {
		appGuid   string
		authToken string
	}{appGuid, authToken})
	fake.recentLogsMutex.Unlock()
	if fake.RecentLogsStub != nil {
		return fake.RecentLogsStub(appGuid, authToken)
	} else {
		return fake.recentLogsReturns.result1, fake.recentLogsReturns.result2
	}
}

func (fake *FakeNoaaConsumer) RecentLogsCallCount() int {
	fake.recentLogsMutex.RLock()
	defer fake.recentLogsMutex.RUnlock()
	return len(fake.recentLogsArgsForCall)
}

func (fake *FakeNoaaConsumer) RecentLogsArgsForCall(i int) (string, string) {
	fake.recentLogsMutex.RLock()
	defer fake.recentLogsMutex.RUnlock()
	return fake.recentLogsArgsForCall[i].appGuid, fake.recentLogsArgsForCall[i].authToken
}

func (fake *FakeNoaaConsumer) RecentLogsReturns(result1 []*events.LogMessage, result2 error) {
	fake.RecentLogsStub = nil
	fake.recentLogsReturns = struct {
		result1 []*events.LogMessage
		result2 error
	}{result1, result2}
}

func (fake *FakeNoaaConsumer) Close() error {
	fake.closeMutex.Lock()
	fake.closeArgsForCall = append(fake.closeArgsForCall, struct{}{})
	fake.closeMutex.Unlock()
	if fake.CloseStub != nil {
		return fake.CloseStub()
	} else {
		return fake.closeReturns.result1
	}
}

func (fake *FakeNoaaConsumer) CloseCallCount() int {
	fake.closeMutex.RLock()
	defer fake.closeMutex.RUnlock()
	return len(fake.closeArgsForCall)
}

func (fake *FakeNoaaConsumer) CloseReturns(result1 error) {
	fake.CloseStub = nil
	fake.closeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeNoaaConsumer) SetOnConnectCallback(cb func()) {
	fake.setOnConnectCallbackMutex.Lock()
	fake.setOnConnectCallbackArgsForCall = append(fake.setOnConnectCallbackArgsForCall, struct {
		cb func()
	}{cb})
	fake.setOnConnectCallbackMutex.Unlock()
	if fake.SetOnConnectCallbackStub != nil {
		fake.SetOnConnectCallbackStub(cb)
	}
}

func (fake *FakeNoaaConsumer) SetOnConnectCallbackCallCount() int {
	fake.setOnConnectCallbackMutex.RLock()
	defer fake.setOnConnectCallbackMutex.RUnlock()
	return len(fake.setOnConnectCallbackArgsForCall)
}

func (fake *FakeNoaaConsumer) SetOnConnectCallbackArgsForCall(i int) func() {
	fake.setOnConnectCallbackMutex.RLock()
	defer fake.setOnConnectCallbackMutex.RUnlock()
	return fake.setOnConnectCallbackArgsForCall[i].cb
}

var _ logs.NoaaConsumer = new(FakeNoaaConsumer)
