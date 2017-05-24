// Code generated by counterfeiter. DO NOT EDIT.
package wrapperfakes

import (
	"sync"
	"time"

	"code.cloudfoundry.org/cli/api/cloudcontroller/wrapper"
)

type FakeRequestLoggerOutput struct {
	DisplayJSONBodyStub        func(body []byte) error
	displayJSONBodyMutex       sync.RWMutex
	displayJSONBodyArgsForCall []struct {
		body []byte
	}
	displayJSONBodyReturns struct {
		result1 error
	}
	displayJSONBodyReturnsOnCall map[int]struct {
		result1 error
	}
	DisplayHeaderStub        func(name string, value string) error
	displayHeaderMutex       sync.RWMutex
	displayHeaderArgsForCall []struct {
		name  string
		value string
	}
	displayHeaderReturns struct {
		result1 error
	}
	displayHeaderReturnsOnCall map[int]struct {
		result1 error
	}
	DisplayHostStub        func(name string) error
	displayHostMutex       sync.RWMutex
	displayHostArgsForCall []struct {
		name string
	}
	displayHostReturns struct {
		result1 error
	}
	displayHostReturnsOnCall map[int]struct {
		result1 error
	}
	DisplayRequestHeaderStub        func(method string, uri string, httpProtocol string) error
	displayRequestHeaderMutex       sync.RWMutex
	displayRequestHeaderArgsForCall []struct {
		method       string
		uri          string
		httpProtocol string
	}
	displayRequestHeaderReturns struct {
		result1 error
	}
	displayRequestHeaderReturnsOnCall map[int]struct {
		result1 error
	}
	DisplayResponseHeaderStub        func(httpProtocol string, status string) error
	displayResponseHeaderMutex       sync.RWMutex
	displayResponseHeaderArgsForCall []struct {
		httpProtocol string
		status       string
	}
	displayResponseHeaderReturns struct {
		result1 error
	}
	displayResponseHeaderReturnsOnCall map[int]struct {
		result1 error
	}
	DisplayTypeStub        func(name string, requestDate time.Time) error
	displayTypeMutex       sync.RWMutex
	displayTypeArgsForCall []struct {
		name        string
		requestDate time.Time
	}
	displayTypeReturns struct {
		result1 error
	}
	displayTypeReturnsOnCall map[int]struct {
		result1 error
	}
	HandleInternalErrorStub        func(err error)
	handleInternalErrorMutex       sync.RWMutex
	handleInternalErrorArgsForCall []struct {
		err error
	}
	StartStub        func() error
	startMutex       sync.RWMutex
	startArgsForCall []struct{}
	startReturns     struct {
		result1 error
	}
	startReturnsOnCall map[int]struct {
		result1 error
	}
	StopStub        func() error
	stopMutex       sync.RWMutex
	stopArgsForCall []struct{}
	stopReturns     struct {
		result1 error
	}
	stopReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRequestLoggerOutput) DisplayJSONBody(body []byte) error {
	var bodyCopy []byte
	if body != nil {
		bodyCopy = make([]byte, len(body))
		copy(bodyCopy, body)
	}
	fake.displayJSONBodyMutex.Lock()
	ret, specificReturn := fake.displayJSONBodyReturnsOnCall[len(fake.displayJSONBodyArgsForCall)]
	fake.displayJSONBodyArgsForCall = append(fake.displayJSONBodyArgsForCall, struct {
		body []byte
	}{bodyCopy})
	fake.recordInvocation("DisplayJSONBody", []interface{}{bodyCopy})
	fake.displayJSONBodyMutex.Unlock()
	if fake.DisplayJSONBodyStub != nil {
		return fake.DisplayJSONBodyStub(body)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayJSONBodyReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayJSONBodyCallCount() int {
	fake.displayJSONBodyMutex.RLock()
	defer fake.displayJSONBodyMutex.RUnlock()
	return len(fake.displayJSONBodyArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayJSONBodyArgsForCall(i int) []byte {
	fake.displayJSONBodyMutex.RLock()
	defer fake.displayJSONBodyMutex.RUnlock()
	return fake.displayJSONBodyArgsForCall[i].body
}

func (fake *FakeRequestLoggerOutput) DisplayJSONBodyReturns(result1 error) {
	fake.DisplayJSONBodyStub = nil
	fake.displayJSONBodyReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayJSONBodyReturnsOnCall(i int, result1 error) {
	fake.DisplayJSONBodyStub = nil
	if fake.displayJSONBodyReturnsOnCall == nil {
		fake.displayJSONBodyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayJSONBodyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayHeader(name string, value string) error {
	fake.displayHeaderMutex.Lock()
	ret, specificReturn := fake.displayHeaderReturnsOnCall[len(fake.displayHeaderArgsForCall)]
	fake.displayHeaderArgsForCall = append(fake.displayHeaderArgsForCall, struct {
		name  string
		value string
	}{name, value})
	fake.recordInvocation("DisplayHeader", []interface{}{name, value})
	fake.displayHeaderMutex.Unlock()
	if fake.DisplayHeaderStub != nil {
		return fake.DisplayHeaderStub(name, value)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayHeaderReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayHeaderCallCount() int {
	fake.displayHeaderMutex.RLock()
	defer fake.displayHeaderMutex.RUnlock()
	return len(fake.displayHeaderArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayHeaderArgsForCall(i int) (string, string) {
	fake.displayHeaderMutex.RLock()
	defer fake.displayHeaderMutex.RUnlock()
	return fake.displayHeaderArgsForCall[i].name, fake.displayHeaderArgsForCall[i].value
}

func (fake *FakeRequestLoggerOutput) DisplayHeaderReturns(result1 error) {
	fake.DisplayHeaderStub = nil
	fake.displayHeaderReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayHeaderReturnsOnCall(i int, result1 error) {
	fake.DisplayHeaderStub = nil
	if fake.displayHeaderReturnsOnCall == nil {
		fake.displayHeaderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayHeaderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayHost(name string) error {
	fake.displayHostMutex.Lock()
	ret, specificReturn := fake.displayHostReturnsOnCall[len(fake.displayHostArgsForCall)]
	fake.displayHostArgsForCall = append(fake.displayHostArgsForCall, struct {
		name string
	}{name})
	fake.recordInvocation("DisplayHost", []interface{}{name})
	fake.displayHostMutex.Unlock()
	if fake.DisplayHostStub != nil {
		return fake.DisplayHostStub(name)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayHostReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayHostCallCount() int {
	fake.displayHostMutex.RLock()
	defer fake.displayHostMutex.RUnlock()
	return len(fake.displayHostArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayHostArgsForCall(i int) string {
	fake.displayHostMutex.RLock()
	defer fake.displayHostMutex.RUnlock()
	return fake.displayHostArgsForCall[i].name
}

func (fake *FakeRequestLoggerOutput) DisplayHostReturns(result1 error) {
	fake.DisplayHostStub = nil
	fake.displayHostReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayHostReturnsOnCall(i int, result1 error) {
	fake.DisplayHostStub = nil
	if fake.displayHostReturnsOnCall == nil {
		fake.displayHostReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayHostReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayRequestHeader(method string, uri string, httpProtocol string) error {
	fake.displayRequestHeaderMutex.Lock()
	ret, specificReturn := fake.displayRequestHeaderReturnsOnCall[len(fake.displayRequestHeaderArgsForCall)]
	fake.displayRequestHeaderArgsForCall = append(fake.displayRequestHeaderArgsForCall, struct {
		method       string
		uri          string
		httpProtocol string
	}{method, uri, httpProtocol})
	fake.recordInvocation("DisplayRequestHeader", []interface{}{method, uri, httpProtocol})
	fake.displayRequestHeaderMutex.Unlock()
	if fake.DisplayRequestHeaderStub != nil {
		return fake.DisplayRequestHeaderStub(method, uri, httpProtocol)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayRequestHeaderReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayRequestHeaderCallCount() int {
	fake.displayRequestHeaderMutex.RLock()
	defer fake.displayRequestHeaderMutex.RUnlock()
	return len(fake.displayRequestHeaderArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayRequestHeaderArgsForCall(i int) (string, string, string) {
	fake.displayRequestHeaderMutex.RLock()
	defer fake.displayRequestHeaderMutex.RUnlock()
	return fake.displayRequestHeaderArgsForCall[i].method, fake.displayRequestHeaderArgsForCall[i].uri, fake.displayRequestHeaderArgsForCall[i].httpProtocol
}

func (fake *FakeRequestLoggerOutput) DisplayRequestHeaderReturns(result1 error) {
	fake.DisplayRequestHeaderStub = nil
	fake.displayRequestHeaderReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayRequestHeaderReturnsOnCall(i int, result1 error) {
	fake.DisplayRequestHeaderStub = nil
	if fake.displayRequestHeaderReturnsOnCall == nil {
		fake.displayRequestHeaderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayRequestHeaderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayResponseHeader(httpProtocol string, status string) error {
	fake.displayResponseHeaderMutex.Lock()
	ret, specificReturn := fake.displayResponseHeaderReturnsOnCall[len(fake.displayResponseHeaderArgsForCall)]
	fake.displayResponseHeaderArgsForCall = append(fake.displayResponseHeaderArgsForCall, struct {
		httpProtocol string
		status       string
	}{httpProtocol, status})
	fake.recordInvocation("DisplayResponseHeader", []interface{}{httpProtocol, status})
	fake.displayResponseHeaderMutex.Unlock()
	if fake.DisplayResponseHeaderStub != nil {
		return fake.DisplayResponseHeaderStub(httpProtocol, status)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayResponseHeaderReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayResponseHeaderCallCount() int {
	fake.displayResponseHeaderMutex.RLock()
	defer fake.displayResponseHeaderMutex.RUnlock()
	return len(fake.displayResponseHeaderArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayResponseHeaderArgsForCall(i int) (string, string) {
	fake.displayResponseHeaderMutex.RLock()
	defer fake.displayResponseHeaderMutex.RUnlock()
	return fake.displayResponseHeaderArgsForCall[i].httpProtocol, fake.displayResponseHeaderArgsForCall[i].status
}

func (fake *FakeRequestLoggerOutput) DisplayResponseHeaderReturns(result1 error) {
	fake.DisplayResponseHeaderStub = nil
	fake.displayResponseHeaderReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayResponseHeaderReturnsOnCall(i int, result1 error) {
	fake.DisplayResponseHeaderStub = nil
	if fake.displayResponseHeaderReturnsOnCall == nil {
		fake.displayResponseHeaderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayResponseHeaderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayType(name string, requestDate time.Time) error {
	fake.displayTypeMutex.Lock()
	ret, specificReturn := fake.displayTypeReturnsOnCall[len(fake.displayTypeArgsForCall)]
	fake.displayTypeArgsForCall = append(fake.displayTypeArgsForCall, struct {
		name        string
		requestDate time.Time
	}{name, requestDate})
	fake.recordInvocation("DisplayType", []interface{}{name, requestDate})
	fake.displayTypeMutex.Unlock()
	if fake.DisplayTypeStub != nil {
		return fake.DisplayTypeStub(name, requestDate)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.displayTypeReturns.result1
}

func (fake *FakeRequestLoggerOutput) DisplayTypeCallCount() int {
	fake.displayTypeMutex.RLock()
	defer fake.displayTypeMutex.RUnlock()
	return len(fake.displayTypeArgsForCall)
}

func (fake *FakeRequestLoggerOutput) DisplayTypeArgsForCall(i int) (string, time.Time) {
	fake.displayTypeMutex.RLock()
	defer fake.displayTypeMutex.RUnlock()
	return fake.displayTypeArgsForCall[i].name, fake.displayTypeArgsForCall[i].requestDate
}

func (fake *FakeRequestLoggerOutput) DisplayTypeReturns(result1 error) {
	fake.DisplayTypeStub = nil
	fake.displayTypeReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) DisplayTypeReturnsOnCall(i int, result1 error) {
	fake.DisplayTypeStub = nil
	if fake.displayTypeReturnsOnCall == nil {
		fake.displayTypeReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.displayTypeReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) HandleInternalError(err error) {
	fake.handleInternalErrorMutex.Lock()
	fake.handleInternalErrorArgsForCall = append(fake.handleInternalErrorArgsForCall, struct {
		err error
	}{err})
	fake.recordInvocation("HandleInternalError", []interface{}{err})
	fake.handleInternalErrorMutex.Unlock()
	if fake.HandleInternalErrorStub != nil {
		fake.HandleInternalErrorStub(err)
	}
}

func (fake *FakeRequestLoggerOutput) HandleInternalErrorCallCount() int {
	fake.handleInternalErrorMutex.RLock()
	defer fake.handleInternalErrorMutex.RUnlock()
	return len(fake.handleInternalErrorArgsForCall)
}

func (fake *FakeRequestLoggerOutput) HandleInternalErrorArgsForCall(i int) error {
	fake.handleInternalErrorMutex.RLock()
	defer fake.handleInternalErrorMutex.RUnlock()
	return fake.handleInternalErrorArgsForCall[i].err
}

func (fake *FakeRequestLoggerOutput) Start() error {
	fake.startMutex.Lock()
	ret, specificReturn := fake.startReturnsOnCall[len(fake.startArgsForCall)]
	fake.startArgsForCall = append(fake.startArgsForCall, struct{}{})
	fake.recordInvocation("Start", []interface{}{})
	fake.startMutex.Unlock()
	if fake.StartStub != nil {
		return fake.StartStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.startReturns.result1
}

func (fake *FakeRequestLoggerOutput) StartCallCount() int {
	fake.startMutex.RLock()
	defer fake.startMutex.RUnlock()
	return len(fake.startArgsForCall)
}

func (fake *FakeRequestLoggerOutput) StartReturns(result1 error) {
	fake.StartStub = nil
	fake.startReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) StartReturnsOnCall(i int, result1 error) {
	fake.StartStub = nil
	if fake.startReturnsOnCall == nil {
		fake.startReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.startReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) Stop() error {
	fake.stopMutex.Lock()
	ret, specificReturn := fake.stopReturnsOnCall[len(fake.stopArgsForCall)]
	fake.stopArgsForCall = append(fake.stopArgsForCall, struct{}{})
	fake.recordInvocation("Stop", []interface{}{})
	fake.stopMutex.Unlock()
	if fake.StopStub != nil {
		return fake.StopStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.stopReturns.result1
}

func (fake *FakeRequestLoggerOutput) StopCallCount() int {
	fake.stopMutex.RLock()
	defer fake.stopMutex.RUnlock()
	return len(fake.stopArgsForCall)
}

func (fake *FakeRequestLoggerOutput) StopReturns(result1 error) {
	fake.StopStub = nil
	fake.stopReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) StopReturnsOnCall(i int, result1 error) {
	fake.StopStub = nil
	if fake.stopReturnsOnCall == nil {
		fake.stopReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.stopReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeRequestLoggerOutput) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.displayJSONBodyMutex.RLock()
	defer fake.displayJSONBodyMutex.RUnlock()
	fake.displayHeaderMutex.RLock()
	defer fake.displayHeaderMutex.RUnlock()
	fake.displayHostMutex.RLock()
	defer fake.displayHostMutex.RUnlock()
	fake.displayRequestHeaderMutex.RLock()
	defer fake.displayRequestHeaderMutex.RUnlock()
	fake.displayResponseHeaderMutex.RLock()
	defer fake.displayResponseHeaderMutex.RUnlock()
	fake.displayTypeMutex.RLock()
	defer fake.displayTypeMutex.RUnlock()
	fake.handleInternalErrorMutex.RLock()
	defer fake.handleInternalErrorMutex.RUnlock()
	fake.startMutex.RLock()
	defer fake.startMutex.RUnlock()
	fake.stopMutex.RLock()
	defer fake.stopMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeRequestLoggerOutput) recordInvocation(key string, args []interface{}) {
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

var _ wrapper.RequestLoggerOutput = new(FakeRequestLoggerOutput)
