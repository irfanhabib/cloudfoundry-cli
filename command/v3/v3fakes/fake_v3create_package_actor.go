// Code generated by counterfeiter. DO NOT EDIT.
package v3fakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/command/v3"
)

type FakeV3CreatePackageActor struct {
	CreateAndUploadPackageByApplicationNameAndSpaceStub        func(appName string, spaceGUID string, bitsPath string) (v3action.Package, v3action.Warnings, error)
	createAndUploadPackageByApplicationNameAndSpaceMutex       sync.RWMutex
	createAndUploadPackageByApplicationNameAndSpaceArgsForCall []struct {
		appName   string
		spaceGUID string
		bitsPath  string
	}
	createAndUploadPackageByApplicationNameAndSpaceReturns struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}
	createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall map[int]struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeV3CreatePackageActor) CreateAndUploadPackageByApplicationNameAndSpace(appName string, spaceGUID string, bitsPath string) (v3action.Package, v3action.Warnings, error) {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall[len(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall)]
	fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall = append(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
		bitsPath  string
	}{appName, spaceGUID, bitsPath})
	fake.recordInvocation("CreateAndUploadPackageByApplicationNameAndSpace", []interface{}{appName, spaceGUID, bitsPath})
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.Unlock()
	if fake.CreateAndUploadPackageByApplicationNameAndSpaceStub != nil {
		return fake.CreateAndUploadPackageByApplicationNameAndSpaceStub(appName, spaceGUID, bitsPath)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result1, fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result2, fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result3
}

func (fake *FakeV3CreatePackageActor) CreateAndUploadPackageByApplicationNameAndSpaceCallCount() int {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	return len(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall)
}

func (fake *FakeV3CreatePackageActor) CreateAndUploadPackageByApplicationNameAndSpaceArgsForCall(i int) (string, string, string) {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	return fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].appName, fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].spaceGUID, fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].bitsPath
}

func (fake *FakeV3CreatePackageActor) CreateAndUploadPackageByApplicationNameAndSpaceReturns(result1 v3action.Package, result2 v3action.Warnings, result3 error) {
	fake.CreateAndUploadPackageByApplicationNameAndSpaceStub = nil
	fake.createAndUploadPackageByApplicationNameAndSpaceReturns = struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3CreatePackageActor) CreateAndUploadPackageByApplicationNameAndSpaceReturnsOnCall(i int, result1 v3action.Package, result2 v3action.Warnings, result3 error) {
	fake.CreateAndUploadPackageByApplicationNameAndSpaceStub = nil
	if fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall == nil {
		fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 v3action.Package
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall[i] = struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3CreatePackageActor) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeV3CreatePackageActor) recordInvocation(key string, args []interface{}) {
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

var _ v3.V3CreatePackageActor = new(FakeV3CreatePackageActor)
