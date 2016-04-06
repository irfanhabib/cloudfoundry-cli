// This file was generated by counterfeiter
package terminalfakes

import (
	"sync"

	"github.com/cloudfoundry/cli/cf/configuration/core_config"
	"github.com/cloudfoundry/cli/cf/terminal"
)

type FakeUI struct {
	PrintPaginatorStub        func(rows []string, err error)
	printPaginatorMutex       sync.RWMutex
	printPaginatorArgsForCall []struct {
		rows []string
		err  error
	}
	SayStub        func(message string, args ...interface{})
	sayMutex       sync.RWMutex
	sayArgsForCall []struct {
		message string
		args    []interface{}
	}
	PrintCapturingNoOutputStub        func(message string, args ...interface{})
	printCapturingNoOutputMutex       sync.RWMutex
	printCapturingNoOutputArgsForCall []struct {
		message string
		args    []interface{}
	}
	WarnStub        func(message string, args ...interface{})
	warnMutex       sync.RWMutex
	warnArgsForCall []struct {
		message string
		args    []interface{}
	}
	AskStub        func(prompt string) (answer string)
	askMutex       sync.RWMutex
	askArgsForCall []struct {
		prompt string
	}
	askReturns struct {
		result1 string
	}
	AskForPasswordStub        func(prompt string) (answer string)
	askForPasswordMutex       sync.RWMutex
	askForPasswordArgsForCall []struct {
		prompt string
	}
	askForPasswordReturns struct {
		result1 string
	}
	ConfirmStub        func(message string) bool
	confirmMutex       sync.RWMutex
	confirmArgsForCall []struct {
		message string
	}
	confirmReturns struct {
		result1 bool
	}
	ConfirmDeleteStub        func(modelType, modelName string) bool
	confirmDeleteMutex       sync.RWMutex
	confirmDeleteArgsForCall []struct {
		modelType string
		modelName string
	}
	confirmDeleteReturns struct {
		result1 bool
	}
	ConfirmDeleteWithAssociationsStub        func(modelType, modelName string) bool
	confirmDeleteWithAssociationsMutex       sync.RWMutex
	confirmDeleteWithAssociationsArgsForCall []struct {
		modelType string
		modelName string
	}
	confirmDeleteWithAssociationsReturns struct {
		result1 bool
	}
	OkStub            func()
	okMutex           sync.RWMutex
	okArgsForCall     []struct{}
	FailedStub        func(message string, args ...interface{})
	failedMutex       sync.RWMutex
	failedArgsForCall []struct {
		message string
		args    []interface{}
	}
	PanicQuietlyStub             func()
	panicQuietlyMutex            sync.RWMutex
	panicQuietlyArgsForCall      []struct{}
	ShowConfigurationStub        func(core_config.Reader)
	showConfigurationMutex       sync.RWMutex
	showConfigurationArgsForCall []struct {
		arg1 core_config.Reader
	}
	LoadingIndicationStub        func()
	loadingIndicationMutex       sync.RWMutex
	loadingIndicationArgsForCall []struct{}
	TableStub                    func(headers []string) *terminal.UITable
	tableMutex                   sync.RWMutex
	tableArgsForCall             []struct {
		headers []string
	}
	tableReturns struct {
		result1 *terminal.UITable
	}
	NotifyUpdateIfNeededStub        func(core_config.Reader)
	notifyUpdateIfNeededMutex       sync.RWMutex
	notifyUpdateIfNeededArgsForCall []struct {
		arg1 core_config.Reader
	}
}

func (fake *FakeUI) PrintPaginator(rows []string, err error) {
	fake.printPaginatorMutex.Lock()
	fake.printPaginatorArgsForCall = append(fake.printPaginatorArgsForCall, struct {
		rows []string
		err  error
	}{rows, err})
	fake.printPaginatorMutex.Unlock()
	if fake.PrintPaginatorStub != nil {
		fake.PrintPaginatorStub(rows, err)
	}
}

func (fake *FakeUI) PrintPaginatorCallCount() int {
	fake.printPaginatorMutex.RLock()
	defer fake.printPaginatorMutex.RUnlock()
	return len(fake.printPaginatorArgsForCall)
}

func (fake *FakeUI) PrintPaginatorArgsForCall(i int) ([]string, error) {
	fake.printPaginatorMutex.RLock()
	defer fake.printPaginatorMutex.RUnlock()
	return fake.printPaginatorArgsForCall[i].rows, fake.printPaginatorArgsForCall[i].err
}

func (fake *FakeUI) Say(message string, args ...interface{}) {
	fake.sayMutex.Lock()
	fake.sayArgsForCall = append(fake.sayArgsForCall, struct {
		message string
		args    []interface{}
	}{message, args})
	fake.sayMutex.Unlock()
	if fake.SayStub != nil {
		fake.SayStub(message, args...)
	}
}

func (fake *FakeUI) SayCallCount() int {
	fake.sayMutex.RLock()
	defer fake.sayMutex.RUnlock()
	return len(fake.sayArgsForCall)
}

func (fake *FakeUI) SayArgsForCall(i int) (string, []interface{}) {
	fake.sayMutex.RLock()
	defer fake.sayMutex.RUnlock()
	return fake.sayArgsForCall[i].message, fake.sayArgsForCall[i].args
}

func (fake *FakeUI) PrintCapturingNoOutput(message string, args ...interface{}) {
	fake.printCapturingNoOutputMutex.Lock()
	fake.printCapturingNoOutputArgsForCall = append(fake.printCapturingNoOutputArgsForCall, struct {
		message string
		args    []interface{}
	}{message, args})
	fake.printCapturingNoOutputMutex.Unlock()
	if fake.PrintCapturingNoOutputStub != nil {
		fake.PrintCapturingNoOutputStub(message, args...)
	}
}

func (fake *FakeUI) PrintCapturingNoOutputCallCount() int {
	fake.printCapturingNoOutputMutex.RLock()
	defer fake.printCapturingNoOutputMutex.RUnlock()
	return len(fake.printCapturingNoOutputArgsForCall)
}

func (fake *FakeUI) PrintCapturingNoOutputArgsForCall(i int) (string, []interface{}) {
	fake.printCapturingNoOutputMutex.RLock()
	defer fake.printCapturingNoOutputMutex.RUnlock()
	return fake.printCapturingNoOutputArgsForCall[i].message, fake.printCapturingNoOutputArgsForCall[i].args
}

func (fake *FakeUI) Warn(message string, args ...interface{}) {
	fake.warnMutex.Lock()
	fake.warnArgsForCall = append(fake.warnArgsForCall, struct {
		message string
		args    []interface{}
	}{message, args})
	fake.warnMutex.Unlock()
	if fake.WarnStub != nil {
		fake.WarnStub(message, args...)
	}
}

func (fake *FakeUI) WarnCallCount() int {
	fake.warnMutex.RLock()
	defer fake.warnMutex.RUnlock()
	return len(fake.warnArgsForCall)
}

func (fake *FakeUI) WarnArgsForCall(i int) (string, []interface{}) {
	fake.warnMutex.RLock()
	defer fake.warnMutex.RUnlock()
	return fake.warnArgsForCall[i].message, fake.warnArgsForCall[i].args
}

func (fake *FakeUI) Ask(prompt string) (answer string) {
	fake.askMutex.Lock()
	fake.askArgsForCall = append(fake.askArgsForCall, struct {
		prompt string
	}{prompt})
	fake.askMutex.Unlock()
	if fake.AskStub != nil {
		return fake.AskStub(prompt)
	} else {
		return fake.askReturns.result1
	}
}

func (fake *FakeUI) AskCallCount() int {
	fake.askMutex.RLock()
	defer fake.askMutex.RUnlock()
	return len(fake.askArgsForCall)
}

func (fake *FakeUI) AskArgsForCall(i int) string {
	fake.askMutex.RLock()
	defer fake.askMutex.RUnlock()
	return fake.askArgsForCall[i].prompt
}

func (fake *FakeUI) AskReturns(result1 string) {
	fake.AskStub = nil
	fake.askReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeUI) AskForPassword(prompt string) (answer string) {
	fake.askForPasswordMutex.Lock()
	fake.askForPasswordArgsForCall = append(fake.askForPasswordArgsForCall, struct {
		prompt string
	}{prompt})
	fake.askForPasswordMutex.Unlock()
	if fake.AskForPasswordStub != nil {
		return fake.AskForPasswordStub(prompt)
	} else {
		return fake.askForPasswordReturns.result1
	}
}

func (fake *FakeUI) AskForPasswordCallCount() int {
	fake.askForPasswordMutex.RLock()
	defer fake.askForPasswordMutex.RUnlock()
	return len(fake.askForPasswordArgsForCall)
}

func (fake *FakeUI) AskForPasswordArgsForCall(i int) string {
	fake.askForPasswordMutex.RLock()
	defer fake.askForPasswordMutex.RUnlock()
	return fake.askForPasswordArgsForCall[i].prompt
}

func (fake *FakeUI) AskForPasswordReturns(result1 string) {
	fake.AskForPasswordStub = nil
	fake.askForPasswordReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeUI) Confirm(message string) bool {
	fake.confirmMutex.Lock()
	fake.confirmArgsForCall = append(fake.confirmArgsForCall, struct {
		message string
	}{message})
	fake.confirmMutex.Unlock()
	if fake.ConfirmStub != nil {
		return fake.ConfirmStub(message)
	} else {
		return fake.confirmReturns.result1
	}
}

func (fake *FakeUI) ConfirmCallCount() int {
	fake.confirmMutex.RLock()
	defer fake.confirmMutex.RUnlock()
	return len(fake.confirmArgsForCall)
}

func (fake *FakeUI) ConfirmArgsForCall(i int) string {
	fake.confirmMutex.RLock()
	defer fake.confirmMutex.RUnlock()
	return fake.confirmArgsForCall[i].message
}

func (fake *FakeUI) ConfirmReturns(result1 bool) {
	fake.ConfirmStub = nil
	fake.confirmReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeUI) ConfirmDelete(modelType string, modelName string) bool {
	fake.confirmDeleteMutex.Lock()
	fake.confirmDeleteArgsForCall = append(fake.confirmDeleteArgsForCall, struct {
		modelType string
		modelName string
	}{modelType, modelName})
	fake.confirmDeleteMutex.Unlock()
	if fake.ConfirmDeleteStub != nil {
		return fake.ConfirmDeleteStub(modelType, modelName)
	} else {
		return fake.confirmDeleteReturns.result1
	}
}

func (fake *FakeUI) ConfirmDeleteCallCount() int {
	fake.confirmDeleteMutex.RLock()
	defer fake.confirmDeleteMutex.RUnlock()
	return len(fake.confirmDeleteArgsForCall)
}

func (fake *FakeUI) ConfirmDeleteArgsForCall(i int) (string, string) {
	fake.confirmDeleteMutex.RLock()
	defer fake.confirmDeleteMutex.RUnlock()
	return fake.confirmDeleteArgsForCall[i].modelType, fake.confirmDeleteArgsForCall[i].modelName
}

func (fake *FakeUI) ConfirmDeleteReturns(result1 bool) {
	fake.ConfirmDeleteStub = nil
	fake.confirmDeleteReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeUI) ConfirmDeleteWithAssociations(modelType string, modelName string) bool {
	fake.confirmDeleteWithAssociationsMutex.Lock()
	fake.confirmDeleteWithAssociationsArgsForCall = append(fake.confirmDeleteWithAssociationsArgsForCall, struct {
		modelType string
		modelName string
	}{modelType, modelName})
	fake.confirmDeleteWithAssociationsMutex.Unlock()
	if fake.ConfirmDeleteWithAssociationsStub != nil {
		return fake.ConfirmDeleteWithAssociationsStub(modelType, modelName)
	} else {
		return fake.confirmDeleteWithAssociationsReturns.result1
	}
}

func (fake *FakeUI) ConfirmDeleteWithAssociationsCallCount() int {
	fake.confirmDeleteWithAssociationsMutex.RLock()
	defer fake.confirmDeleteWithAssociationsMutex.RUnlock()
	return len(fake.confirmDeleteWithAssociationsArgsForCall)
}

func (fake *FakeUI) ConfirmDeleteWithAssociationsArgsForCall(i int) (string, string) {
	fake.confirmDeleteWithAssociationsMutex.RLock()
	defer fake.confirmDeleteWithAssociationsMutex.RUnlock()
	return fake.confirmDeleteWithAssociationsArgsForCall[i].modelType, fake.confirmDeleteWithAssociationsArgsForCall[i].modelName
}

func (fake *FakeUI) ConfirmDeleteWithAssociationsReturns(result1 bool) {
	fake.ConfirmDeleteWithAssociationsStub = nil
	fake.confirmDeleteWithAssociationsReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeUI) Ok() {
	fake.okMutex.Lock()
	fake.okArgsForCall = append(fake.okArgsForCall, struct{}{})
	fake.okMutex.Unlock()
	if fake.OkStub != nil {
		fake.OkStub()
	}
}

func (fake *FakeUI) OkCallCount() int {
	fake.okMutex.RLock()
	defer fake.okMutex.RUnlock()
	return len(fake.okArgsForCall)
}

func (fake *FakeUI) Failed(message string, args ...interface{}) {
	fake.failedMutex.Lock()
	fake.failedArgsForCall = append(fake.failedArgsForCall, struct {
		message string
		args    []interface{}
	}{message, args})
	fake.failedMutex.Unlock()
	if fake.FailedStub != nil {
		fake.FailedStub(message, args...)
	}
}

func (fake *FakeUI) FailedCallCount() int {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return len(fake.failedArgsForCall)
}

func (fake *FakeUI) FailedArgsForCall(i int) (string, []interface{}) {
	fake.failedMutex.RLock()
	defer fake.failedMutex.RUnlock()
	return fake.failedArgsForCall[i].message, fake.failedArgsForCall[i].args
}

func (fake *FakeUI) PanicQuietly() {
	fake.panicQuietlyMutex.Lock()
	fake.panicQuietlyArgsForCall = append(fake.panicQuietlyArgsForCall, struct{}{})
	fake.panicQuietlyMutex.Unlock()
	if fake.PanicQuietlyStub != nil {
		fake.PanicQuietlyStub()
	}
}

func (fake *FakeUI) PanicQuietlyCallCount() int {
	fake.panicQuietlyMutex.RLock()
	defer fake.panicQuietlyMutex.RUnlock()
	return len(fake.panicQuietlyArgsForCall)
}

func (fake *FakeUI) ShowConfiguration(arg1 core_config.Reader) {
	fake.showConfigurationMutex.Lock()
	fake.showConfigurationArgsForCall = append(fake.showConfigurationArgsForCall, struct {
		arg1 core_config.Reader
	}{arg1})
	fake.showConfigurationMutex.Unlock()
	if fake.ShowConfigurationStub != nil {
		fake.ShowConfigurationStub(arg1)
	}
}

func (fake *FakeUI) ShowConfigurationCallCount() int {
	fake.showConfigurationMutex.RLock()
	defer fake.showConfigurationMutex.RUnlock()
	return len(fake.showConfigurationArgsForCall)
}

func (fake *FakeUI) ShowConfigurationArgsForCall(i int) core_config.Reader {
	fake.showConfigurationMutex.RLock()
	defer fake.showConfigurationMutex.RUnlock()
	return fake.showConfigurationArgsForCall[i].arg1
}

func (fake *FakeUI) LoadingIndication() {
	fake.loadingIndicationMutex.Lock()
	fake.loadingIndicationArgsForCall = append(fake.loadingIndicationArgsForCall, struct{}{})
	fake.loadingIndicationMutex.Unlock()
	if fake.LoadingIndicationStub != nil {
		fake.LoadingIndicationStub()
	}
}

func (fake *FakeUI) LoadingIndicationCallCount() int {
	fake.loadingIndicationMutex.RLock()
	defer fake.loadingIndicationMutex.RUnlock()
	return len(fake.loadingIndicationArgsForCall)
}

func (fake *FakeUI) Table(headers []string) *terminal.UITable {
	fake.tableMutex.Lock()
	fake.tableArgsForCall = append(fake.tableArgsForCall, struct {
		headers []string
	}{headers})
	fake.tableMutex.Unlock()
	if fake.TableStub != nil {
		return fake.TableStub(headers)
	} else {
		return fake.tableReturns.result1
	}
}

func (fake *FakeUI) TableCallCount() int {
	fake.tableMutex.RLock()
	defer fake.tableMutex.RUnlock()
	return len(fake.tableArgsForCall)
}

func (fake *FakeUI) TableArgsForCall(i int) []string {
	fake.tableMutex.RLock()
	defer fake.tableMutex.RUnlock()
	return fake.tableArgsForCall[i].headers
}

func (fake *FakeUI) TableReturns(result1 *terminal.UITable) {
	fake.TableStub = nil
	fake.tableReturns = struct {
		result1 *terminal.UITable
	}{result1}
}

func (fake *FakeUI) NotifyUpdateIfNeeded(arg1 core_config.Reader) {
	fake.notifyUpdateIfNeededMutex.Lock()
	fake.notifyUpdateIfNeededArgsForCall = append(fake.notifyUpdateIfNeededArgsForCall, struct {
		arg1 core_config.Reader
	}{arg1})
	fake.notifyUpdateIfNeededMutex.Unlock()
	if fake.NotifyUpdateIfNeededStub != nil {
		fake.NotifyUpdateIfNeededStub(arg1)
	}
}

func (fake *FakeUI) NotifyUpdateIfNeededCallCount() int {
	fake.notifyUpdateIfNeededMutex.RLock()
	defer fake.notifyUpdateIfNeededMutex.RUnlock()
	return len(fake.notifyUpdateIfNeededArgsForCall)
}

func (fake *FakeUI) NotifyUpdateIfNeededArgsForCall(i int) core_config.Reader {
	fake.notifyUpdateIfNeededMutex.RLock()
	defer fake.notifyUpdateIfNeededMutex.RUnlock()
	return fake.notifyUpdateIfNeededArgsForCall[i].arg1
}

var _ terminal.UI = new(FakeUI)
