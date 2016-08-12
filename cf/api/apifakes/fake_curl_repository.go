// This file was generated by counterfeiter
package apifakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/api"
)

type FakeCurlRepository struct {
	RequestStub        func(method, path, header, body string) (resHeaders string, resBody string, apiErr error)
	requestMutex       sync.RWMutex
	requestArgsForCall []struct {
		method string
		path   string
		header string
		body   string
	}
	requestReturns struct {
		result1 string
		result2 string
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeCurlRepository) Request(method string, path string, header string, body string) (resHeaders string, resBody string, apiErr error) {
	fake.requestMutex.Lock()
	fake.requestArgsForCall = append(fake.requestArgsForCall, struct {
		method string
		path   string
		header string
		body   string
	}{method, path, header, body})
	fake.recordInvocation("Request", []interface{}{method, path, header, body})
	fake.requestMutex.Unlock()
	if fake.RequestStub != nil {
		return fake.RequestStub(method, path, header, body)
	} else {
		return fake.requestReturns.result1, fake.requestReturns.result2, fake.requestReturns.result3
	}
}

func (fake *FakeCurlRepository) RequestCallCount() int {
	fake.requestMutex.RLock()
	defer fake.requestMutex.RUnlock()
	return len(fake.requestArgsForCall)
}

func (fake *FakeCurlRepository) RequestArgsForCall(i int) (string, string, string, string) {
	fake.requestMutex.RLock()
	defer fake.requestMutex.RUnlock()
	return fake.requestArgsForCall[i].method, fake.requestArgsForCall[i].path, fake.requestArgsForCall[i].header, fake.requestArgsForCall[i].body
}

func (fake *FakeCurlRepository) RequestReturns(result1 string, result2 string, result3 error) {
	fake.RequestStub = nil
	fake.requestReturns = struct {
		result1 string
		result2 string
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeCurlRepository) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.requestMutex.RLock()
	defer fake.requestMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeCurlRepository) recordInvocation(key string, args []interface{}) {
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

var _ api.CurlRepository = new(FakeCurlRepository)
