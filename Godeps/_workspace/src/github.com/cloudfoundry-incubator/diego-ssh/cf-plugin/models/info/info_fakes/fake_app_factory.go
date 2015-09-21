// This file was generated by counterfeiter
package info_fakes

import (
	"sync"

	"github.com/cloudfoundry-incubator/diego-ssh/cf-plugin/models/info"
)

type FakeInfoFactory struct {
	GetStub        func() (info.Info, error)
	getMutex       sync.RWMutex
	getArgsForCall []struct{}
	getReturns     struct {
		result1 info.Info
		result2 error
	}
}

func (fake *FakeInfoFactory) Get() (info.Info, error) {
	fake.getMutex.Lock()
	fake.getArgsForCall = append(fake.getArgsForCall, struct{}{})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub()
	} else {
		return fake.getReturns.result1, fake.getReturns.result2
	}
}

func (fake *FakeInfoFactory) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *FakeInfoFactory) GetReturns(result1 info.Info, result2 error) {
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 info.Info
		result2 error
	}{result1, result2}
}

var _ info.InfoFactory = new(FakeInfoFactory)
