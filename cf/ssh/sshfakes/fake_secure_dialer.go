// This file was generated by counterfeiter
package sshfakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/ssh"
	"golang.org/x/crypto/ssh"
)

type FakeSecureDialer struct {
	DialStub        func(network, address string, config *ssh.ClientConfig) (sshCmd.SecureClient, error)
	dialMutex       sync.RWMutex
	dialArgsForCall []struct {
		network string
		address string
		config  *ssh.ClientConfig
	}
	dialReturns struct {
		result1 sshCmd.SecureClient
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSecureDialer) Dial(network string, address string, config *ssh.ClientConfig) (sshCmd.SecureClient, error) {
	fake.dialMutex.Lock()
	fake.dialArgsForCall = append(fake.dialArgsForCall, struct {
		network string
		address string
		config  *ssh.ClientConfig
	}{network, address, config})
	fake.recordInvocation("Dial", []interface{}{network, address, config})
	fake.dialMutex.Unlock()
	if fake.DialStub != nil {
		return fake.DialStub(network, address, config)
	} else {
		return fake.dialReturns.result1, fake.dialReturns.result2
	}
}

func (fake *FakeSecureDialer) DialCallCount() int {
	fake.dialMutex.RLock()
	defer fake.dialMutex.RUnlock()
	return len(fake.dialArgsForCall)
}

func (fake *FakeSecureDialer) DialArgsForCall(i int) (string, string, *ssh.ClientConfig) {
	fake.dialMutex.RLock()
	defer fake.dialMutex.RUnlock()
	return fake.dialArgsForCall[i].network, fake.dialArgsForCall[i].address, fake.dialArgsForCall[i].config
}

func (fake *FakeSecureDialer) DialReturns(result1 sshCmd.SecureClient, result2 error) {
	fake.DialStub = nil
	fake.dialReturns = struct {
		result1 sshCmd.SecureClient
		result2 error
	}{result1, result2}
}

func (fake *FakeSecureDialer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.dialMutex.RLock()
	defer fake.dialMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeSecureDialer) recordInvocation(key string, args []interface{}) {
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

var _ sshCmd.SecureDialer = new(FakeSecureDialer)
