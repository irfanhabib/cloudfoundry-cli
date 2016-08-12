// This file was generated by counterfeiter
package servicefakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/commands/service"
	"github.com/cloudfoundry/cli/cf/models"
)

type FakeRouteServiceUnbinder struct {
	UnbindRouteStub        func(route models.Route, serviceInstance models.ServiceInstance) error
	unbindRouteMutex       sync.RWMutex
	unbindRouteArgsForCall []struct {
		route           models.Route
		serviceInstance models.ServiceInstance
	}
	unbindRouteReturns struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRouteServiceUnbinder) UnbindRoute(route models.Route, serviceInstance models.ServiceInstance) error {
	fake.unbindRouteMutex.Lock()
	fake.unbindRouteArgsForCall = append(fake.unbindRouteArgsForCall, struct {
		route           models.Route
		serviceInstance models.ServiceInstance
	}{route, serviceInstance})
	fake.recordInvocation("UnbindRoute", []interface{}{route, serviceInstance})
	fake.unbindRouteMutex.Unlock()
	if fake.UnbindRouteStub != nil {
		return fake.UnbindRouteStub(route, serviceInstance)
	} else {
		return fake.unbindRouteReturns.result1
	}
}

func (fake *FakeRouteServiceUnbinder) UnbindRouteCallCount() int {
	fake.unbindRouteMutex.RLock()
	defer fake.unbindRouteMutex.RUnlock()
	return len(fake.unbindRouteArgsForCall)
}

func (fake *FakeRouteServiceUnbinder) UnbindRouteArgsForCall(i int) (models.Route, models.ServiceInstance) {
	fake.unbindRouteMutex.RLock()
	defer fake.unbindRouteMutex.RUnlock()
	return fake.unbindRouteArgsForCall[i].route, fake.unbindRouteArgsForCall[i].serviceInstance
}

func (fake *FakeRouteServiceUnbinder) UnbindRouteReturns(result1 error) {
	fake.UnbindRouteStub = nil
	fake.unbindRouteReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRouteServiceUnbinder) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.unbindRouteMutex.RLock()
	defer fake.unbindRouteMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeRouteServiceUnbinder) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ service.RouteServiceUnbinder = new(FakeRouteServiceUnbinder)
