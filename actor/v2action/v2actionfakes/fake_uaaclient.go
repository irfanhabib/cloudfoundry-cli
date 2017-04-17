// This file was generated by counterfeiter
package v2actionfakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v2action"
	"code.cloudfoundry.org/cli/api/uaa"
)

type FakeUAAClient struct {
	CreateUserStub        func(username string, password string, origin string) (uaa.User, error)
	createUserMutex       sync.RWMutex
	createUserArgsForCall []struct {
		username string
		password string
		origin   string
	}
	createUserReturns struct {
		result1 uaa.User
		result2 error
	}
	createUserReturnsOnCall map[int]struct {
		result1 uaa.User
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeUAAClient) CreateUser(username string, password string, origin string) (uaa.User, error) {
	fake.createUserMutex.Lock()
	ret, specificReturn := fake.createUserReturnsOnCall[len(fake.createUserArgsForCall)]
	fake.createUserArgsForCall = append(fake.createUserArgsForCall, struct {
		username string
		password string
		origin   string
	}{username, password, origin})
	fake.recordInvocation("CreateUser", []interface{}{username, password, origin})
	fake.createUserMutex.Unlock()
	if fake.CreateUserStub != nil {
		return fake.CreateUserStub(username, password, origin)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.createUserReturns.result1, fake.createUserReturns.result2
}

func (fake *FakeUAAClient) CreateUserCallCount() int {
	fake.createUserMutex.RLock()
	defer fake.createUserMutex.RUnlock()
	return len(fake.createUserArgsForCall)
}

func (fake *FakeUAAClient) CreateUserArgsForCall(i int) (string, string, string) {
	fake.createUserMutex.RLock()
	defer fake.createUserMutex.RUnlock()
	return fake.createUserArgsForCall[i].username, fake.createUserArgsForCall[i].password, fake.createUserArgsForCall[i].origin
}

func (fake *FakeUAAClient) CreateUserReturns(result1 uaa.User, result2 error) {
	fake.CreateUserStub = nil
	fake.createUserReturns = struct {
		result1 uaa.User
		result2 error
	}{result1, result2}
}

func (fake *FakeUAAClient) CreateUserReturnsOnCall(i int, result1 uaa.User, result2 error) {
	fake.CreateUserStub = nil
	if fake.createUserReturnsOnCall == nil {
		fake.createUserReturnsOnCall = make(map[int]struct {
			result1 uaa.User
			result2 error
		})
	}
	fake.createUserReturnsOnCall[i] = struct {
		result1 uaa.User
		result2 error
	}{result1, result2}
}

func (fake *FakeUAAClient) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.createUserMutex.RLock()
	defer fake.createUserMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeUAAClient) recordInvocation(key string, args []interface{}) {
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

var _ v2action.UAAClient = new(FakeUAAClient)
