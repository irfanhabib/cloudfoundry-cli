// This file was generated by counterfeiter
package apifakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/api"
	"github.com/cloudfoundry/cli/cf/models"
)

type FakeServiceBindingRepository struct {
	CreateStub        func(instanceGUID string, appGUID string, paramsMap map[string]interface{}) error
	createMutex       sync.RWMutex
	createArgsForCall []struct {
		instanceGUID string
		appGUID      string
		paramsMap    map[string]interface{}
	}
	createReturns struct {
		result1 error
	}
	DeleteStub        func(instance models.ServiceInstance, appGUID string) (bool, error)
	deleteMutex       sync.RWMutex
	deleteArgsForCall []struct {
		instance models.ServiceInstance
		appGUID  string
	}
	deleteReturns struct {
		result1 bool
		result2 error
	}
	ListAllForServiceStub        func(instanceGUID string) ([]models.ServiceBindingFields, error)
	listAllForServiceMutex       sync.RWMutex
	listAllForServiceArgsForCall []struct {
		instanceGUID string
	}
	listAllForServiceReturns struct {
		result1 []models.ServiceBindingFields
		result2 error
	}
}

func (fake *FakeServiceBindingRepository) Create(instanceGUID string, appGUID string, paramsMap map[string]interface{}) error {
	fake.createMutex.Lock()
	fake.createArgsForCall = append(fake.createArgsForCall, struct {
		instanceGUID string
		appGUID      string
		paramsMap    map[string]interface{}
	}{instanceGUID, appGUID, paramsMap})
	fake.createMutex.Unlock()
	if fake.CreateStub != nil {
		return fake.CreateStub(instanceGUID, appGUID, paramsMap)
	} else {
		return fake.createReturns.result1
	}
}

func (fake *FakeServiceBindingRepository) CreateCallCount() int {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return len(fake.createArgsForCall)
}

func (fake *FakeServiceBindingRepository) CreateArgsForCall(i int) (string, string, map[string]interface{}) {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return fake.createArgsForCall[i].instanceGUID, fake.createArgsForCall[i].appGUID, fake.createArgsForCall[i].paramsMap
}

func (fake *FakeServiceBindingRepository) CreateReturns(result1 error) {
	fake.CreateStub = nil
	fake.createReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeServiceBindingRepository) Delete(instance models.ServiceInstance, appGUID string) (bool, error) {
	fake.deleteMutex.Lock()
	fake.deleteArgsForCall = append(fake.deleteArgsForCall, struct {
		instance models.ServiceInstance
		appGUID  string
	}{instance, appGUID})
	fake.deleteMutex.Unlock()
	if fake.DeleteStub != nil {
		return fake.DeleteStub(instance, appGUID)
	} else {
		return fake.deleteReturns.result1, fake.deleteReturns.result2
	}
}

func (fake *FakeServiceBindingRepository) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *FakeServiceBindingRepository) DeleteArgsForCall(i int) (models.ServiceInstance, string) {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return fake.deleteArgsForCall[i].instance, fake.deleteArgsForCall[i].appGUID
}

func (fake *FakeServiceBindingRepository) DeleteReturns(result1 bool, result2 error) {
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 bool
		result2 error
	}{result1, result2}
}

func (fake *FakeServiceBindingRepository) ListAllForService(instanceGUID string) ([]models.ServiceBindingFields, error) {
	fake.listAllForServiceMutex.Lock()
	fake.listAllForServiceArgsForCall = append(fake.listAllForServiceArgsForCall, struct {
		instanceGUID string
	}{instanceGUID})
	fake.listAllForServiceMutex.Unlock()
	if fake.ListAllForServiceStub != nil {
		return fake.ListAllForServiceStub(instanceGUID)
	} else {
		return fake.listAllForServiceReturns.result1, fake.listAllForServiceReturns.result2
	}
}

func (fake *FakeServiceBindingRepository) ListAllForServiceCallCount() int {
	fake.listAllForServiceMutex.RLock()
	defer fake.listAllForServiceMutex.RUnlock()
	return len(fake.listAllForServiceArgsForCall)
}

func (fake *FakeServiceBindingRepository) ListAllForServiceArgsForCall(i int) string {
	fake.listAllForServiceMutex.RLock()
	defer fake.listAllForServiceMutex.RUnlock()
	return fake.listAllForServiceArgsForCall[i].instanceGUID
}

func (fake *FakeServiceBindingRepository) ListAllForServiceReturns(result1 []models.ServiceBindingFields, result2 error) {
	fake.ListAllForServiceStub = nil
	fake.listAllForServiceReturns = struct {
		result1 []models.ServiceBindingFields
		result2 error
	}{result1, result2}
}

var _ api.ServiceBindingRepository = new(FakeServiceBindingRepository)
