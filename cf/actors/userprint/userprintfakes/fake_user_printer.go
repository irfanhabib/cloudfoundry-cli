// This file was generated by counterfeiter
package userprintfakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/actors/userprint"
)

type FakeUserPrinter struct {
	PrintUsersStub        func(guid string, username string)
	printUsersMutex       sync.RWMutex
	printUsersArgsForCall []struct {
		guid     string
		username string
	}
}

func (fake *FakeUserPrinter) PrintUsers(guid string, username string) {
	fake.printUsersMutex.Lock()
	fake.printUsersArgsForCall = append(fake.printUsersArgsForCall, struct {
		guid     string
		username string
	}{guid, username})
	fake.printUsersMutex.Unlock()
	if fake.PrintUsersStub != nil {
		fake.PrintUsersStub(guid, username)
	}
}

func (fake *FakeUserPrinter) PrintUsersCallCount() int {
	fake.printUsersMutex.RLock()
	defer fake.printUsersMutex.RUnlock()
	return len(fake.printUsersArgsForCall)
}

func (fake *FakeUserPrinter) PrintUsersArgsForCall(i int) (string, string) {
	fake.printUsersMutex.RLock()
	defer fake.printUsersMutex.RUnlock()
	return fake.printUsersArgsForCall[i].guid, fake.printUsersArgsForCall[i].username
}

var _ userprint.UserPrinter = new(FakeUserPrinter)
