// This file was generated by counterfeiter
package v3actionsfakes

import (
	"net/url"
	"sync"

	"code.cloudfoundry.org/cli/actors/v3actions"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
)

type FakeCloudControllerClient struct {
	RunTaskStub        func(appGUID string, command string) (ccv3.Task, ccv3.Warnings, error)
	runTaskMutex       sync.RWMutex
	runTaskArgsForCall []struct {
		appGUID string
		command string
	}
	runTaskReturns struct {
		result1 ccv3.Task
		result2 ccv3.Warnings
		result3 error
	}
	GetApplicationsStub        func(query url.Values) ([]ccv3.Application, ccv3.Warnings, error)
	getApplicationsMutex       sync.RWMutex
	getApplicationsArgsForCall []struct {
		query url.Values
	}
	getApplicationsReturns struct {
		result1 []ccv3.Application
		result2 ccv3.Warnings
		result3 error
	}
	GetApplicationTasksStub        func(appGUID string, query url.Values) ([]ccv3.Task, ccv3.Warnings, error)
	getApplicationTasksMutex       sync.RWMutex
	getApplicationTasksArgsForCall []struct {
		appGUID string
		query   url.Values
	}
	getApplicationTasksReturns struct {
		result1 []ccv3.Task
		result2 ccv3.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeCloudControllerClient) RunTask(appGUID string, command string) (ccv3.Task, ccv3.Warnings, error) {
	fake.runTaskMutex.Lock()
	fake.runTaskArgsForCall = append(fake.runTaskArgsForCall, struct {
		appGUID string
		command string
	}{appGUID, command})
	fake.recordInvocation("RunTask", []interface{}{appGUID, command})
	fake.runTaskMutex.Unlock()
	if fake.RunTaskStub != nil {
		return fake.RunTaskStub(appGUID, command)
	} else {
		return fake.runTaskReturns.result1, fake.runTaskReturns.result2, fake.runTaskReturns.result3
	}
}

func (fake *FakeCloudControllerClient) RunTaskCallCount() int {
	fake.runTaskMutex.RLock()
	defer fake.runTaskMutex.RUnlock()
	return len(fake.runTaskArgsForCall)
}

func (fake *FakeCloudControllerClient) RunTaskArgsForCall(i int) (string, string) {
	fake.runTaskMutex.RLock()
	defer fake.runTaskMutex.RUnlock()
	return fake.runTaskArgsForCall[i].appGUID, fake.runTaskArgsForCall[i].command
}

func (fake *FakeCloudControllerClient) RunTaskReturns(result1 ccv3.Task, result2 ccv3.Warnings, result3 error) {
	fake.RunTaskStub = nil
	fake.runTaskReturns = struct {
		result1 ccv3.Task
		result2 ccv3.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeCloudControllerClient) GetApplications(query url.Values) ([]ccv3.Application, ccv3.Warnings, error) {
	fake.getApplicationsMutex.Lock()
	fake.getApplicationsArgsForCall = append(fake.getApplicationsArgsForCall, struct {
		query url.Values
	}{query})
	fake.recordInvocation("GetApplications", []interface{}{query})
	fake.getApplicationsMutex.Unlock()
	if fake.GetApplicationsStub != nil {
		return fake.GetApplicationsStub(query)
	} else {
		return fake.getApplicationsReturns.result1, fake.getApplicationsReturns.result2, fake.getApplicationsReturns.result3
	}
}

func (fake *FakeCloudControllerClient) GetApplicationsCallCount() int {
	fake.getApplicationsMutex.RLock()
	defer fake.getApplicationsMutex.RUnlock()
	return len(fake.getApplicationsArgsForCall)
}

func (fake *FakeCloudControllerClient) GetApplicationsArgsForCall(i int) url.Values {
	fake.getApplicationsMutex.RLock()
	defer fake.getApplicationsMutex.RUnlock()
	return fake.getApplicationsArgsForCall[i].query
}

func (fake *FakeCloudControllerClient) GetApplicationsReturns(result1 []ccv3.Application, result2 ccv3.Warnings, result3 error) {
	fake.GetApplicationsStub = nil
	fake.getApplicationsReturns = struct {
		result1 []ccv3.Application
		result2 ccv3.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeCloudControllerClient) GetApplicationTasks(appGUID string, query url.Values) ([]ccv3.Task, ccv3.Warnings, error) {
	fake.getApplicationTasksMutex.Lock()
	fake.getApplicationTasksArgsForCall = append(fake.getApplicationTasksArgsForCall, struct {
		appGUID string
		query   url.Values
	}{appGUID, query})
	fake.recordInvocation("GetApplicationTasks", []interface{}{appGUID, query})
	fake.getApplicationTasksMutex.Unlock()
	if fake.GetApplicationTasksStub != nil {
		return fake.GetApplicationTasksStub(appGUID, query)
	} else {
		return fake.getApplicationTasksReturns.result1, fake.getApplicationTasksReturns.result2, fake.getApplicationTasksReturns.result3
	}
}

func (fake *FakeCloudControllerClient) GetApplicationTasksCallCount() int {
	fake.getApplicationTasksMutex.RLock()
	defer fake.getApplicationTasksMutex.RUnlock()
	return len(fake.getApplicationTasksArgsForCall)
}

func (fake *FakeCloudControllerClient) GetApplicationTasksArgsForCall(i int) (string, url.Values) {
	fake.getApplicationTasksMutex.RLock()
	defer fake.getApplicationTasksMutex.RUnlock()
	return fake.getApplicationTasksArgsForCall[i].appGUID, fake.getApplicationTasksArgsForCall[i].query
}

func (fake *FakeCloudControllerClient) GetApplicationTasksReturns(result1 []ccv3.Task, result2 ccv3.Warnings, result3 error) {
	fake.GetApplicationTasksStub = nil
	fake.getApplicationTasksReturns = struct {
		result1 []ccv3.Task
		result2 ccv3.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeCloudControllerClient) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.runTaskMutex.RLock()
	defer fake.runTaskMutex.RUnlock()
	fake.getApplicationsMutex.RLock()
	defer fake.getApplicationsMutex.RUnlock()
	fake.getApplicationTasksMutex.RLock()
	defer fake.getApplicationTasksMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeCloudControllerClient) recordInvocation(key string, args []interface{}) {
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

var _ v3actions.CloudControllerClient = new(FakeCloudControllerClient)
