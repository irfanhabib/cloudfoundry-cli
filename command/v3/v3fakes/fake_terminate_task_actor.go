// This file was generated by counterfeiter
package v3fakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/command/v3"
)

type FakeTerminateTaskActor struct {
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
	GetTaskBySequenceIDAndApplicationStub        func(sequenceID int, appGUID string) (v3action.Task, v3action.Warnings, error)
	getTaskBySequenceIDAndApplicationMutex       sync.RWMutex
	getTaskBySequenceIDAndApplicationArgsForCall []struct {
		sequenceID int
		appGUID    string
	}
	getTaskBySequenceIDAndApplicationReturns struct {
		result1 v3action.Task
		result2 v3action.Warnings
		result3 error
	}
	TerminateTaskStub        func(taskGUID string) (v3action.Task, v3action.Warnings, error)
	terminateTaskMutex       sync.RWMutex
	terminateTaskArgsForCall []struct {
		taskGUID string
	}
	terminateTaskReturns struct {
		result1 v3action.Task
		result2 v3action.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeTerminateTaskActor) GetApplicationByNameAndSpace(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error) {
	fake.getApplicationByNameAndSpaceMutex.Lock()
	fake.getApplicationByNameAndSpaceArgsForCall = append(fake.getApplicationByNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
	}{appName, spaceGUID})
	fake.recordInvocation("GetApplicationByNameAndSpace", []interface{}{appName, spaceGUID})
	fake.getApplicationByNameAndSpaceMutex.Unlock()
	if fake.GetApplicationByNameAndSpaceStub != nil {
		return fake.GetApplicationByNameAndSpaceStub(appName, spaceGUID)
	} else {
		return fake.getApplicationByNameAndSpaceReturns.result1, fake.getApplicationByNameAndSpaceReturns.result2, fake.getApplicationByNameAndSpaceReturns.result3
	}
}

func (fake *FakeTerminateTaskActor) GetApplicationByNameAndSpaceCallCount() int {
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	return len(fake.getApplicationByNameAndSpaceArgsForCall)
}

func (fake *FakeTerminateTaskActor) GetApplicationByNameAndSpaceArgsForCall(i int) (string, string) {
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	return fake.getApplicationByNameAndSpaceArgsForCall[i].appName, fake.getApplicationByNameAndSpaceArgsForCall[i].spaceGUID
}

func (fake *FakeTerminateTaskActor) GetApplicationByNameAndSpaceReturns(result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.GetApplicationByNameAndSpaceStub = nil
	fake.getApplicationByNameAndSpaceReturns = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeTerminateTaskActor) GetTaskBySequenceIDAndApplication(sequenceID int, appGUID string) (v3action.Task, v3action.Warnings, error) {
	fake.getTaskBySequenceIDAndApplicationMutex.Lock()
	fake.getTaskBySequenceIDAndApplicationArgsForCall = append(fake.getTaskBySequenceIDAndApplicationArgsForCall, struct {
		sequenceID int
		appGUID    string
	}{sequenceID, appGUID})
	fake.recordInvocation("GetTaskBySequenceIDAndApplication", []interface{}{sequenceID, appGUID})
	fake.getTaskBySequenceIDAndApplicationMutex.Unlock()
	if fake.GetTaskBySequenceIDAndApplicationStub != nil {
		return fake.GetTaskBySequenceIDAndApplicationStub(sequenceID, appGUID)
	} else {
		return fake.getTaskBySequenceIDAndApplicationReturns.result1, fake.getTaskBySequenceIDAndApplicationReturns.result2, fake.getTaskBySequenceIDAndApplicationReturns.result3
	}
}

func (fake *FakeTerminateTaskActor) GetTaskBySequenceIDAndApplicationCallCount() int {
	fake.getTaskBySequenceIDAndApplicationMutex.RLock()
	defer fake.getTaskBySequenceIDAndApplicationMutex.RUnlock()
	return len(fake.getTaskBySequenceIDAndApplicationArgsForCall)
}

func (fake *FakeTerminateTaskActor) GetTaskBySequenceIDAndApplicationArgsForCall(i int) (int, string) {
	fake.getTaskBySequenceIDAndApplicationMutex.RLock()
	defer fake.getTaskBySequenceIDAndApplicationMutex.RUnlock()
	return fake.getTaskBySequenceIDAndApplicationArgsForCall[i].sequenceID, fake.getTaskBySequenceIDAndApplicationArgsForCall[i].appGUID
}

func (fake *FakeTerminateTaskActor) GetTaskBySequenceIDAndApplicationReturns(result1 v3action.Task, result2 v3action.Warnings, result3 error) {
	fake.GetTaskBySequenceIDAndApplicationStub = nil
	fake.getTaskBySequenceIDAndApplicationReturns = struct {
		result1 v3action.Task
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeTerminateTaskActor) TerminateTask(taskGUID string) (v3action.Task, v3action.Warnings, error) {
	fake.terminateTaskMutex.Lock()
	fake.terminateTaskArgsForCall = append(fake.terminateTaskArgsForCall, struct {
		taskGUID string
	}{taskGUID})
	fake.recordInvocation("TerminateTask", []interface{}{taskGUID})
	fake.terminateTaskMutex.Unlock()
	if fake.TerminateTaskStub != nil {
		return fake.TerminateTaskStub(taskGUID)
	} else {
		return fake.terminateTaskReturns.result1, fake.terminateTaskReturns.result2, fake.terminateTaskReturns.result3
	}
}

func (fake *FakeTerminateTaskActor) TerminateTaskCallCount() int {
	fake.terminateTaskMutex.RLock()
	defer fake.terminateTaskMutex.RUnlock()
	return len(fake.terminateTaskArgsForCall)
}

func (fake *FakeTerminateTaskActor) TerminateTaskArgsForCall(i int) string {
	fake.terminateTaskMutex.RLock()
	defer fake.terminateTaskMutex.RUnlock()
	return fake.terminateTaskArgsForCall[i].taskGUID
}

func (fake *FakeTerminateTaskActor) TerminateTaskReturns(result1 v3action.Task, result2 v3action.Warnings, result3 error) {
	fake.TerminateTaskStub = nil
	fake.terminateTaskReturns = struct {
		result1 v3action.Task
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeTerminateTaskActor) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getApplicationByNameAndSpaceMutex.RLock()
	defer fake.getApplicationByNameAndSpaceMutex.RUnlock()
	fake.getTaskBySequenceIDAndApplicationMutex.RLock()
	defer fake.getTaskBySequenceIDAndApplicationMutex.RUnlock()
	fake.terminateTaskMutex.RLock()
	defer fake.terminateTaskMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeTerminateTaskActor) recordInvocation(key string, args []interface{}) {
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

var _ v3.TerminateTaskActor = new(FakeTerminateTaskActor)
