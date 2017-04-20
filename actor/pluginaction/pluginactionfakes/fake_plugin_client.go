// This file was generated by counterfeiter
package pluginactionfakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/pluginaction"
	"code.cloudfoundry.org/cli/api/plugin"
)

type FakePluginClient struct {
	GetPluginRepositoryStub        func(repositoryURL string) (plugin.PluginRepository, error)
	getPluginRepositoryMutex       sync.RWMutex
	getPluginRepositoryArgsForCall []struct {
		repositoryURL string
	}
	getPluginRepositoryReturns struct {
		result1 plugin.PluginRepository
		result2 error
	}
	getPluginRepositoryReturnsOnCall map[int]struct {
		result1 plugin.PluginRepository
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakePluginClient) GetPluginRepository(repositoryURL string) (plugin.PluginRepository, error) {
	fake.getPluginRepositoryMutex.Lock()
	ret, specificReturn := fake.getPluginRepositoryReturnsOnCall[len(fake.getPluginRepositoryArgsForCall)]
	fake.getPluginRepositoryArgsForCall = append(fake.getPluginRepositoryArgsForCall, struct {
		repositoryURL string
	}{repositoryURL})
	fake.recordInvocation("GetPluginRepository", []interface{}{repositoryURL})
	fake.getPluginRepositoryMutex.Unlock()
	if fake.GetPluginRepositoryStub != nil {
		return fake.GetPluginRepositoryStub(repositoryURL)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getPluginRepositoryReturns.result1, fake.getPluginRepositoryReturns.result2
}

func (fake *FakePluginClient) GetPluginRepositoryCallCount() int {
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	return len(fake.getPluginRepositoryArgsForCall)
}

func (fake *FakePluginClient) GetPluginRepositoryArgsForCall(i int) string {
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	return fake.getPluginRepositoryArgsForCall[i].repositoryURL
}

func (fake *FakePluginClient) GetPluginRepositoryReturns(result1 plugin.PluginRepository, result2 error) {
	fake.GetPluginRepositoryStub = nil
	fake.getPluginRepositoryReturns = struct {
		result1 plugin.PluginRepository
		result2 error
	}{result1, result2}
}

func (fake *FakePluginClient) GetPluginRepositoryReturnsOnCall(i int, result1 plugin.PluginRepository, result2 error) {
	fake.GetPluginRepositoryStub = nil
	if fake.getPluginRepositoryReturnsOnCall == nil {
		fake.getPluginRepositoryReturnsOnCall = make(map[int]struct {
			result1 plugin.PluginRepository
			result2 error
		})
	}
	fake.getPluginRepositoryReturnsOnCall[i] = struct {
		result1 plugin.PluginRepository
		result2 error
	}{result1, result2}
}

func (fake *FakePluginClient) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	return fake.invocations
}

func (fake *FakePluginClient) recordInvocation(key string, args []interface{}) {
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

var _ pluginaction.PluginClient = new(FakePluginClient)
