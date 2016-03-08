// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/trace"
)

type FakePrinter struct {
	PrintStub        func(v ...interface{})
	printMutex       sync.RWMutex
	printArgsForCall []struct {
		v []interface{}
	}
	PrintfStub        func(format string, v ...interface{})
	printfMutex       sync.RWMutex
	printfArgsForCall []struct {
		format string
		v      []interface{}
	}
	PrintlnStub        func(v ...interface{})
	printlnMutex       sync.RWMutex
	printlnArgsForCall []struct {
		v []interface{}
	}
}

func (fake *FakePrinter) Print(v ...interface{}) {
	fake.printMutex.Lock()
	fake.printArgsForCall = append(fake.printArgsForCall, struct {
		v []interface{}
	}{v})
	fake.printMutex.Unlock()
	if fake.PrintStub != nil {
		fake.PrintStub(v...)
	}
}

func (fake *FakePrinter) PrintCallCount() int {
	fake.printMutex.RLock()
	defer fake.printMutex.RUnlock()
	return len(fake.printArgsForCall)
}

func (fake *FakePrinter) PrintArgsForCall(i int) []interface{} {
	fake.printMutex.RLock()
	defer fake.printMutex.RUnlock()
	return fake.printArgsForCall[i].v
}

func (fake *FakePrinter) Printf(format string, v ...interface{}) {
	fake.printfMutex.Lock()
	fake.printfArgsForCall = append(fake.printfArgsForCall, struct {
		format string
		v      []interface{}
	}{format, v})
	fake.printfMutex.Unlock()
	if fake.PrintfStub != nil {
		fake.PrintfStub(format, v...)
	}
}

func (fake *FakePrinter) PrintfCallCount() int {
	fake.printfMutex.RLock()
	defer fake.printfMutex.RUnlock()
	return len(fake.printfArgsForCall)
}

func (fake *FakePrinter) PrintfArgsForCall(i int) (string, []interface{}) {
	fake.printfMutex.RLock()
	defer fake.printfMutex.RUnlock()
	return fake.printfArgsForCall[i].format, fake.printfArgsForCall[i].v
}

func (fake *FakePrinter) Println(v ...interface{}) {
	fake.printlnMutex.Lock()
	fake.printlnArgsForCall = append(fake.printlnArgsForCall, struct {
		v []interface{}
	}{v})
	fake.printlnMutex.Unlock()
	if fake.PrintlnStub != nil {
		fake.PrintlnStub(v...)
	}
}

func (fake *FakePrinter) PrintlnCallCount() int {
	fake.printlnMutex.RLock()
	defer fake.printlnMutex.RUnlock()
	return len(fake.printlnArgsForCall)
}

func (fake *FakePrinter) PrintlnArgsForCall(i int) []interface{} {
	fake.printlnMutex.RLock()
	defer fake.printlnMutex.RUnlock()
	return fake.printlnArgsForCall[i].v
}

var _ trace.Printer = new(FakePrinter)
