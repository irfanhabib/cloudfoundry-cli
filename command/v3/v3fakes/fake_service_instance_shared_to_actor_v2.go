// Code generated by counterfeiter. DO NOT EDIT.
package v3fakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/command/v3"
)

type FakeServiceInstanceSharedToActorV2 struct {
	GetSharedToSpaceGUIDStub        func(serviceInstanceName string, sourceSpaceGUID string, sharedToOrgName string, sharedToSpaceName string) (string, v2action.Warnings, error)
	getSharedToSpaceGUIDMutex       sync.RWMutex
	getSharedToSpaceGUIDArgsForCall []struct {
		serviceInstanceName string
		sourceSpaceGUID     string
		sharedToOrgName     string
		sharedToSpaceName   string
	}
	getSharedToSpaceGUIDReturns struct {
		result1 string
		result2 v2action.Warnings
		result3 error
	}
	getSharedToSpaceGUIDReturnsOnCall map[int]struct {
		result1 string
		result2 v2action.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeServiceInstanceSharedToActorV2) GetSharedToSpaceGUID(serviceInstanceName string, sourceSpaceGUID string, sharedToOrgName string, sharedToSpaceName string) (string, v2action.Warnings, error) {
	fake.getSharedToSpaceGUIDMutex.Lock()
	ret, specificReturn := fake.getSharedToSpaceGUIDReturnsOnCall[len(fake.getSharedToSpaceGUIDArgsForCall)]
	fake.getSharedToSpaceGUIDArgsForCall = append(fake.getSharedToSpaceGUIDArgsForCall, struct {
		serviceInstanceName string
		sourceSpaceGUID     string
		sharedToOrgName     string
		sharedToSpaceName   string
	}{serviceInstanceName, sourceSpaceGUID, sharedToOrgName, sharedToSpaceName})
	fake.recordInvocation("GetSharedToSpaceGUID", []interface{}{serviceInstanceName, sourceSpaceGUID, sharedToOrgName, sharedToSpaceName})
	fake.getSharedToSpaceGUIDMutex.Unlock()
	if fake.GetSharedToSpaceGUIDStub != nil {
		return fake.GetSharedToSpaceGUIDStub(serviceInstanceName, sourceSpaceGUID, sharedToOrgName, sharedToSpaceName)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.getSharedToSpaceGUIDReturns.result1, fake.getSharedToSpaceGUIDReturns.result2, fake.getSharedToSpaceGUIDReturns.result3
}

func (fake *FakeServiceInstanceSharedToActorV2) GetSharedToSpaceGUIDCallCount() int {
	fake.getSharedToSpaceGUIDMutex.RLock()
	defer fake.getSharedToSpaceGUIDMutex.RUnlock()
	return len(fake.getSharedToSpaceGUIDArgsForCall)
}

func (fake *FakeServiceInstanceSharedToActorV2) GetSharedToSpaceGUIDArgsForCall(i int) (string, string, string, string) {
	fake.getSharedToSpaceGUIDMutex.RLock()
	defer fake.getSharedToSpaceGUIDMutex.RUnlock()
	return fake.getSharedToSpaceGUIDArgsForCall[i].serviceInstanceName, fake.getSharedToSpaceGUIDArgsForCall[i].sourceSpaceGUID, fake.getSharedToSpaceGUIDArgsForCall[i].sharedToOrgName, fake.getSharedToSpaceGUIDArgsForCall[i].sharedToSpaceName
}

func (fake *FakeServiceInstanceSharedToActorV2) GetSharedToSpaceGUIDReturns(result1 string, result2 v2action.Warnings, result3 error) {
	fake.GetSharedToSpaceGUIDStub = nil
	fake.getSharedToSpaceGUIDReturns = struct {
		result1 string
		result2 v2action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeServiceInstanceSharedToActorV2) GetSharedToSpaceGUIDReturnsOnCall(i int, result1 string, result2 v2action.Warnings, result3 error) {
	fake.GetSharedToSpaceGUIDStub = nil
	if fake.getSharedToSpaceGUIDReturnsOnCall == nil {
		fake.getSharedToSpaceGUIDReturnsOnCall = make(map[int]struct {
			result1 string
			result2 v2action.Warnings
			result3 error
		})
	}
	fake.getSharedToSpaceGUIDReturnsOnCall[i] = struct {
		result1 string
		result2 v2action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeServiceInstanceSharedToActorV2) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getSharedToSpaceGUIDMutex.RLock()
	defer fake.getSharedToSpaceGUIDMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeServiceInstanceSharedToActorV2) recordInvocation(key string, args []interface{}) {
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

var _ v3.ServiceInstanceSharedToActorV2 = new(FakeServiceInstanceSharedToActorV2)
