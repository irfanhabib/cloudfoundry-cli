// Code generated by counterfeiter. DO NOT EDIT.
package v3fakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/command/v3"
)

type FakeV3ScaleActor struct {
	GetApplicationByNameAndSpaceStub        func(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error)
	getApplicationByNameAndSpaceMutex       sync.RWMutex
	getApplicationByNameAndSpaceArgsForCall []struct {
		appName   string
		spaceGUID string
	}
	getApplicationByNameAndSpaceReturns struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	getApplicationByNameAndSpaceReturnsOnCall map[int]struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	GetProcessByApplicationStub        func(appGUID string) (ccv3.Process, v3action.Warnings, error)
	getProcessByApplicationMutex       sync.RWMutex
	getProcessByApplicationArgsForCall []struct {
		appGUID string
	}
	getProcessByApplicationReturns struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}
	getProcessByApplicationReturnsOnCall map[int]struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}
	ScaleProcessByApplicationStub        func(appGUID string, process ccv3.Process) (ccv3.Process, v3action.Warnings, error)
	scaleProcessByApplicationMutex       sync.RWMutex
	scaleProcessByApplicationArgsForCall []struct {
		appGUID string
		process ccv3.Process
	}
	scaleProcessByApplicationReturns struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}
	scaleProcessByApplicationReturnsOnCall map[int]struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeV3ScaleActor) GetApplicationByNameAndSpace(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error) {
	fake.getApplicationByNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.getApplicationByNameAndSpaceReturnsOnCall[len(fake.getApplicationByNameAndSpaceArgsForCall)]
	fake.getApplicationByNameAndSpaceArgsForCall = append(fake.getApplicationByNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
	}{appName, spaceGUID})
	fake.recordInvocation("GetApplicationByNameAndSpace", []interface{}{appName, spaceGUID})
	fake.getApplicationByNameAndSpaceMutex.Unlock()
	if fake.GetApplicationByNameAndSpaceStub != nil {
		return fake.GetApplicationByNameAndSpaceStub(appName, spaceGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.getApplicationByNameAndSpaceReturns.result1, fake.getApplicationByNameAndSpaceReturns.result2, fake.getApplicationByNameAndSpaceReturns.result3
}

func (fake *FakeV3ScaleActor) GetApplicationByNameAndSpaceCallCount() int {
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	return len(fake.getApplicationByNameAndSpaceArgsForCall)
}

func (fake *FakeV3ScaleActor) GetApplicationByNameAndSpaceArgsForCall(i int) (string, string) {
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	return fake.getApplicationByNameAndSpaceArgsForCall[i].appName, fake.getApplicationByNameAndSpaceArgsForCall[i].spaceGUID
}

func (fake *FakeV3ScaleActor) GetApplicationByNameAndSpaceReturns(result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.GetApplicationByNameAndSpaceStub = nil
	fake.getApplicationByNameAndSpaceReturns = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) GetApplicationByNameAndSpaceReturnsOnCall(i int, result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.GetApplicationByNameAndSpaceStub = nil
	if fake.getApplicationByNameAndSpaceReturnsOnCall == nil {
		fake.getApplicationByNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 v3action.Application
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.getApplicationByNameAndSpaceReturnsOnCall[i] = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) GetProcessByApplication(appGUID string) (ccv3.Process, v3action.Warnings, error) {
	fake.getProcessByApplicationMutex.Lock()
	ret, specificReturn := fake.getProcessByApplicationReturnsOnCall[len(fake.getProcessByApplicationArgsForCall)]
	fake.getProcessByApplicationArgsForCall = append(fake.getProcessByApplicationArgsForCall, struct {
		appGUID string
	}{appGUID})
	fake.recordInvocation("GetProcessByApplication", []interface{}{appGUID})
	fake.getProcessByApplicationMutex.Unlock()
	if fake.GetProcessByApplicationStub != nil {
		return fake.GetProcessByApplicationStub(appGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.getProcessByApplicationReturns.result1, fake.getProcessByApplicationReturns.result2, fake.getProcessByApplicationReturns.result3
}

func (fake *FakeV3ScaleActor) GetProcessByApplicationCallCount() int {
	fake.getProcessByApplicationMutex.RLock()
	defer fake.getProcessByApplicationMutex.RUnlock()
	return len(fake.getProcessByApplicationArgsForCall)
}

func (fake *FakeV3ScaleActor) GetProcessByApplicationArgsForCall(i int) string {
	fake.getProcessByApplicationMutex.RLock()
	defer fake.getProcessByApplicationMutex.RUnlock()
	return fake.getProcessByApplicationArgsForCall[i].appGUID
}

func (fake *FakeV3ScaleActor) GetProcessByApplicationReturns(result1 ccv3.Process, result2 v3action.Warnings, result3 error) {
	fake.GetProcessByApplicationStub = nil
	fake.getProcessByApplicationReturns = struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) GetProcessByApplicationReturnsOnCall(i int, result1 ccv3.Process, result2 v3action.Warnings, result3 error) {
	fake.GetProcessByApplicationStub = nil
	if fake.getProcessByApplicationReturnsOnCall == nil {
		fake.getProcessByApplicationReturnsOnCall = make(map[int]struct {
			result1 ccv3.Process
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.getProcessByApplicationReturnsOnCall[i] = struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) ScaleProcessByApplication(appGUID string, process ccv3.Process) (ccv3.Process, v3action.Warnings, error) {
	fake.scaleProcessByApplicationMutex.Lock()
	ret, specificReturn := fake.scaleProcessByApplicationReturnsOnCall[len(fake.scaleProcessByApplicationArgsForCall)]
	fake.scaleProcessByApplicationArgsForCall = append(fake.scaleProcessByApplicationArgsForCall, struct {
		appGUID string
		process ccv3.Process
	}{appGUID, process})
	fake.recordInvocation("ScaleProcessByApplication", []interface{}{appGUID, process})
	fake.scaleProcessByApplicationMutex.Unlock()
	if fake.ScaleProcessByApplicationStub != nil {
		return fake.ScaleProcessByApplicationStub(appGUID, process)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.scaleProcessByApplicationReturns.result1, fake.scaleProcessByApplicationReturns.result2, fake.scaleProcessByApplicationReturns.result3
}

func (fake *FakeV3ScaleActor) ScaleProcessByApplicationCallCount() int {
	fake.scaleProcessByApplicationMutex.RLock()
	defer fake.scaleProcessByApplicationMutex.RUnlock()
	return len(fake.scaleProcessByApplicationArgsForCall)
}

func (fake *FakeV3ScaleActor) ScaleProcessByApplicationArgsForCall(i int) (string, ccv3.Process) {
	fake.scaleProcessByApplicationMutex.RLock()
	defer fake.scaleProcessByApplicationMutex.RUnlock()
	return fake.scaleProcessByApplicationArgsForCall[i].appGUID, fake.scaleProcessByApplicationArgsForCall[i].process
}

func (fake *FakeV3ScaleActor) ScaleProcessByApplicationReturns(result1 ccv3.Process, result2 v3action.Warnings, result3 error) {
	fake.ScaleProcessByApplicationStub = nil
	fake.scaleProcessByApplicationReturns = struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) ScaleProcessByApplicationReturnsOnCall(i int, result1 ccv3.Process, result2 v3action.Warnings, result3 error) {
	fake.ScaleProcessByApplicationStub = nil
	if fake.scaleProcessByApplicationReturnsOnCall == nil {
		fake.scaleProcessByApplicationReturnsOnCall = make(map[int]struct {
			result1 ccv3.Process
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.scaleProcessByApplicationReturnsOnCall[i] = struct {
		result1 ccv3.Process
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3ScaleActor) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	fake.getProcessByApplicationMutex.RLock()
	defer fake.getProcessByApplicationMutex.RUnlock()
	fake.scaleProcessByApplicationMutex.RLock()
	defer fake.scaleProcessByApplicationMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeV3ScaleActor) recordInvocation(key string, args []interface{}) {
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

var _ v3.V3ScaleActor = new(FakeV3ScaleActor)
