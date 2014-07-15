// This file was generated by counterfeiter
package fakes

import (
	"github.com/cloudfoundry/cli/cf/actors"
	"github.com/cloudfoundry/cli/cf/models"
	"sync"
)

type FakeServiceActor struct {
	GetBrokersWithDependenciesStub        func() ([]models.ServiceBroker, error)
	getBrokersWithDependenciesMutex       sync.RWMutex
	getBrokersWithDependenciesArgsForCall []struct{}
	getBrokersWithDependenciesReturns     struct {
		result1 []models.ServiceBroker
		result2 error
	}
}

func (fake *FakeServiceActor) GetBrokersWithDependencies() ([]models.ServiceBroker, error) {
	fake.getBrokersWithDependenciesMutex.Lock()
	defer fake.getBrokersWithDependenciesMutex.Unlock()
	fake.getBrokersWithDependenciesArgsForCall = append(fake.getBrokersWithDependenciesArgsForCall, struct{}{})
	if fake.GetBrokersWithDependenciesStub != nil {
		return fake.GetBrokersWithDependenciesStub()
	} else {
		return fake.getBrokersWithDependenciesReturns.result1, fake.getBrokersWithDependenciesReturns.result2
	}
}

func (fake *FakeServiceActor) GetBrokersWithDependenciesCallCount() int {
	fake.getBrokersWithDependenciesMutex.RLock()
	defer fake.getBrokersWithDependenciesMutex.RUnlock()
	return len(fake.getBrokersWithDependenciesArgsForCall)
}

func (fake *FakeServiceActor) GetBrokersWithDependenciesReturns(result1 []models.ServiceBroker, result2 error) {
	fake.GetBrokersWithDependenciesStub = nil
	fake.getBrokersWithDependenciesReturns = struct {
		result1 []models.ServiceBroker
		result2 error
	}{result1, result2}
}

var _ actors.ServiceActor = new(FakeServiceActor)
