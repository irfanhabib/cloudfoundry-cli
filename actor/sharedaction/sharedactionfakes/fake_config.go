// This file was generated by counterfeiter
package sharedactionfakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/sharedaction"
)

type FakeConfig struct {
	AccessTokenStub        func() string
	accessTokenMutex       sync.RWMutex
	accessTokenArgsForCall []struct{}
	accessTokenReturns     struct {
		result1 string
	}
	BinaryNameStub        func() string
	binaryNameMutex       sync.RWMutex
	binaryNameArgsForCall []struct{}
	binaryNameReturns     struct {
		result1 string
	}
	HasTargetedOrganizationStub        func() bool
	hasTargetedOrganizationMutex       sync.RWMutex
	hasTargetedOrganizationArgsForCall []struct{}
	hasTargetedOrganizationReturns     struct {
		result1 bool
	}
	HasTargetedSpaceStub        func() bool
	hasTargetedSpaceMutex       sync.RWMutex
	hasTargetedSpaceArgsForCall []struct{}
	hasTargetedSpaceReturns     struct {
		result1 bool
	}
	RefreshTokenStub        func() string
	refreshTokenMutex       sync.RWMutex
	refreshTokenArgsForCall []struct{}
	refreshTokenReturns     struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeConfig) AccessToken() string {
	fake.accessTokenMutex.Lock()
	fake.accessTokenArgsForCall = append(fake.accessTokenArgsForCall, struct{}{})
	fake.recordInvocation("AccessToken", []interface{}{})
	fake.accessTokenMutex.Unlock()
	if fake.AccessTokenStub != nil {
		return fake.AccessTokenStub()
	} else {
		return fake.accessTokenReturns.result1
	}
}

func (fake *FakeConfig) AccessTokenCallCount() int {
	fake.accessTokenMutex.RLock()
	defer fake.accessTokenMutex.RUnlock()
	return len(fake.accessTokenArgsForCall)
}

func (fake *FakeConfig) AccessTokenReturns(result1 string) {
	fake.AccessTokenStub = nil
	fake.accessTokenReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeConfig) BinaryName() string {
	fake.binaryNameMutex.Lock()
	fake.binaryNameArgsForCall = append(fake.binaryNameArgsForCall, struct{}{})
	fake.recordInvocation("BinaryName", []interface{}{})
	fake.binaryNameMutex.Unlock()
	if fake.BinaryNameStub != nil {
		return fake.BinaryNameStub()
	} else {
		return fake.binaryNameReturns.result1
	}
}

func (fake *FakeConfig) BinaryNameCallCount() int {
	fake.binaryNameMutex.RLock()
	defer fake.binaryNameMutex.RUnlock()
	return len(fake.binaryNameArgsForCall)
}

func (fake *FakeConfig) BinaryNameReturns(result1 string) {
	fake.BinaryNameStub = nil
	fake.binaryNameReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeConfig) HasTargetedOrganization() bool {
	fake.hasTargetedOrganizationMutex.Lock()
	fake.hasTargetedOrganizationArgsForCall = append(fake.hasTargetedOrganizationArgsForCall, struct{}{})
	fake.recordInvocation("HasTargetedOrganization", []interface{}{})
	fake.hasTargetedOrganizationMutex.Unlock()
	if fake.HasTargetedOrganizationStub != nil {
		return fake.HasTargetedOrganizationStub()
	} else {
		return fake.hasTargetedOrganizationReturns.result1
	}
}

func (fake *FakeConfig) HasTargetedOrganizationCallCount() int {
	fake.hasTargetedOrganizationMutex.RLock()
	defer fake.hasTargetedOrganizationMutex.RUnlock()
	return len(fake.hasTargetedOrganizationArgsForCall)
}

func (fake *FakeConfig) HasTargetedOrganizationReturns(result1 bool) {
	fake.HasTargetedOrganizationStub = nil
	fake.hasTargetedOrganizationReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeConfig) HasTargetedSpace() bool {
	fake.hasTargetedSpaceMutex.Lock()
	fake.hasTargetedSpaceArgsForCall = append(fake.hasTargetedSpaceArgsForCall, struct{}{})
	fake.recordInvocation("HasTargetedSpace", []interface{}{})
	fake.hasTargetedSpaceMutex.Unlock()
	if fake.HasTargetedSpaceStub != nil {
		return fake.HasTargetedSpaceStub()
	} else {
		return fake.hasTargetedSpaceReturns.result1
	}
}

func (fake *FakeConfig) HasTargetedSpaceCallCount() int {
	fake.hasTargetedSpaceMutex.RLock()
	defer fake.hasTargetedSpaceMutex.RUnlock()
	return len(fake.hasTargetedSpaceArgsForCall)
}

func (fake *FakeConfig) HasTargetedSpaceReturns(result1 bool) {
	fake.HasTargetedSpaceStub = nil
	fake.hasTargetedSpaceReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeConfig) RefreshToken() string {
	fake.refreshTokenMutex.Lock()
	fake.refreshTokenArgsForCall = append(fake.refreshTokenArgsForCall, struct{}{})
	fake.recordInvocation("RefreshToken", []interface{}{})
	fake.refreshTokenMutex.Unlock()
	if fake.RefreshTokenStub != nil {
		return fake.RefreshTokenStub()
	} else {
		return fake.refreshTokenReturns.result1
	}
}

func (fake *FakeConfig) RefreshTokenCallCount() int {
	fake.refreshTokenMutex.RLock()
	defer fake.refreshTokenMutex.RUnlock()
	return len(fake.refreshTokenArgsForCall)
}

func (fake *FakeConfig) RefreshTokenReturns(result1 string) {
	fake.RefreshTokenStub = nil
	fake.refreshTokenReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeConfig) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.accessTokenMutex.RLock()
	defer fake.accessTokenMutex.RUnlock()
	fake.binaryNameMutex.RLock()
	defer fake.binaryNameMutex.RUnlock()
	fake.hasTargetedOrganizationMutex.RLock()
	defer fake.hasTargetedOrganizationMutex.RUnlock()
	fake.hasTargetedSpaceMutex.RLock()
	defer fake.hasTargetedSpaceMutex.RUnlock()
	fake.refreshTokenMutex.RLock()
	defer fake.refreshTokenMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeConfig) recordInvocation(key string, args []interface{}) {
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

var _ sharedaction.Config = new(FakeConfig)
