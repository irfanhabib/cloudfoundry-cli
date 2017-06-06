// Code generated by counterfeiter. DO NOT EDIT.
package v3fakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/v3action"
	"code.cloudfoundry.org/cli/command/v3"
)

type FakeV3PushActor struct {
	CreateApplicationByNameAndSpaceStub        func(name string, spaceGUID string) (v3action.Application, v3action.Warnings, error)
	createApplicationByNameAndSpaceMutex       sync.RWMutex
	createApplicationByNameAndSpaceArgsForCall []struct {
		name      string
		spaceGUID string
	}
	createApplicationByNameAndSpaceReturns struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	createApplicationByNameAndSpaceReturnsOnCall map[int]struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	CreateAndUploadPackageByApplicationNameAndSpaceStub        func(appName string, spaceGUID string, bitsPath string) (v3action.Package, v3action.Warnings, error)
	createAndUploadPackageByApplicationNameAndSpaceMutex       sync.RWMutex
	createAndUploadPackageByApplicationNameAndSpaceArgsForCall []struct {
		appName   string
		spaceGUID string
		bitsPath  string
	}
	createAndUploadPackageByApplicationNameAndSpaceReturns struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}
	createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall map[int]struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}
	StagePackageStub        func(packageGUID string) (<-chan v3action.Build, <-chan v3action.Warnings, <-chan error)
	stagePackageMutex       sync.RWMutex
	stagePackageArgsForCall []struct {
		packageGUID string
	}
	stagePackageReturns struct {
		result1 <-chan v3action.Build
		result2 <-chan v3action.Warnings
		result3 <-chan error
	}
	stagePackageReturnsOnCall map[int]struct {
		result1 <-chan v3action.Build
		result2 <-chan v3action.Warnings
		result3 <-chan error
	}
	GetStreamingLogsForApplicationByNameAndSpaceStub        func(appName string, spaceGUID string, client v3action.NOAAClient) (<-chan *v3action.LogMessage, <-chan error, v3action.Warnings, error)
	getStreamingLogsForApplicationByNameAndSpaceMutex       sync.RWMutex
	getStreamingLogsForApplicationByNameAndSpaceArgsForCall []struct {
		appName   string
		spaceGUID string
		client    v3action.NOAAClient
	}
	getStreamingLogsForApplicationByNameAndSpaceReturns struct {
		result1 <-chan *v3action.LogMessage
		result2 <-chan error
		result3 v3action.Warnings
		result4 error
	}
	getStreamingLogsForApplicationByNameAndSpaceReturnsOnCall map[int]struct {
		result1 <-chan *v3action.LogMessage
		result2 <-chan error
		result3 v3action.Warnings
		result4 error
	}
	SetApplicationDropletStub        func(appName string, spaceGUID string, dropletGUID string) (v3action.Warnings, error)
	setApplicationDropletMutex       sync.RWMutex
	setApplicationDropletArgsForCall []struct {
		appName     string
		spaceGUID   string
		dropletGUID string
	}
	setApplicationDropletReturns struct {
		result1 v3action.Warnings
		result2 error
	}
	setApplicationDropletReturnsOnCall map[int]struct {
		result1 v3action.Warnings
		result2 error
	}
	StartApplicationStub        func(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error)
	startApplicationMutex       sync.RWMutex
	startApplicationArgsForCall []struct {
		appName   string
		spaceGUID string
	}
	startApplicationReturns struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	startApplicationReturnsOnCall map[int]struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}
	GetApplicationSummaryByNameAndSpaceStub        func(appName string, spaceGUID string) (v3action.ApplicationSummary, v3action.Warnings, error)
	getApplicationSummaryByNameAndSpaceMutex       sync.RWMutex
	getApplicationSummaryByNameAndSpaceArgsForCall []struct {
		appName   string
		spaceGUID string
	}
	getApplicationSummaryByNameAndSpaceReturns struct {
		result1 v3action.ApplicationSummary
		result2 v3action.Warnings
		result3 error
	}
	getApplicationSummaryByNameAndSpaceReturnsOnCall map[int]struct {
		result1 v3action.ApplicationSummary
		result2 v3action.Warnings
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeV3PushActor) CreateApplicationByNameAndSpace(name string, spaceGUID string) (v3action.Application, v3action.Warnings, error) {
	fake.createApplicationByNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.createApplicationByNameAndSpaceReturnsOnCall[len(fake.createApplicationByNameAndSpaceArgsForCall)]
	fake.createApplicationByNameAndSpaceArgsForCall = append(fake.createApplicationByNameAndSpaceArgsForCall, struct {
		name      string
		spaceGUID string
	}{name, spaceGUID})
	fake.recordInvocation("CreateApplicationByNameAndSpace", []interface{}{name, spaceGUID})
	fake.createApplicationByNameAndSpaceMutex.Unlock()
	if fake.CreateApplicationByNameAndSpaceStub != nil {
		return fake.CreateApplicationByNameAndSpaceStub(name, spaceGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.createApplicationByNameAndSpaceReturns.result1, fake.createApplicationByNameAndSpaceReturns.result2, fake.createApplicationByNameAndSpaceReturns.result3
}

func (fake *FakeV3PushActor) CreateApplicationByNameAndSpaceCallCount() int {
	fake.createApplicationByNameAndSpaceMutex.RLock()
	defer fake.createApplicationByNameAndSpaceMutex.RUnlock()
	return len(fake.createApplicationByNameAndSpaceArgsForCall)
}

func (fake *FakeV3PushActor) CreateApplicationByNameAndSpaceArgsForCall(i int) (string, string) {
	fake.createApplicationByNameAndSpaceMutex.RLock()
	defer fake.createApplicationByNameAndSpaceMutex.RUnlock()
	return fake.createApplicationByNameAndSpaceArgsForCall[i].name, fake.createApplicationByNameAndSpaceArgsForCall[i].spaceGUID
}

func (fake *FakeV3PushActor) CreateApplicationByNameAndSpaceReturns(result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.CreateApplicationByNameAndSpaceStub = nil
	fake.createApplicationByNameAndSpaceReturns = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) CreateApplicationByNameAndSpaceReturnsOnCall(i int, result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.CreateApplicationByNameAndSpaceStub = nil
	if fake.createApplicationByNameAndSpaceReturnsOnCall == nil {
		fake.createApplicationByNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 v3action.Application
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.createApplicationByNameAndSpaceReturnsOnCall[i] = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) CreateAndUploadPackageByApplicationNameAndSpace(appName string, spaceGUID string, bitsPath string) (v3action.Package, v3action.Warnings, error) {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall[len(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall)]
	fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall = append(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
		bitsPath  string
	}{appName, spaceGUID, bitsPath})
	fake.recordInvocation("CreateAndUploadPackageByApplicationNameAndSpace", []interface{}{appName, spaceGUID, bitsPath})
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.Unlock()
	if fake.CreateAndUploadPackageByApplicationNameAndSpaceStub != nil {
		return fake.CreateAndUploadPackageByApplicationNameAndSpaceStub(appName, spaceGUID, bitsPath)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result1, fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result2, fake.createAndUploadPackageByApplicationNameAndSpaceReturns.result3
}

func (fake *FakeV3PushActor) CreateAndUploadPackageByApplicationNameAndSpaceCallCount() int {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	return len(fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall)
}

func (fake *FakeV3PushActor) CreateAndUploadPackageByApplicationNameAndSpaceArgsForCall(i int) (string, string, string) {
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	return fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].appName, fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].spaceGUID, fake.createAndUploadPackageByApplicationNameAndSpaceArgsForCall[i].bitsPath
}

func (fake *FakeV3PushActor) CreateAndUploadPackageByApplicationNameAndSpaceReturns(result1 v3action.Package, result2 v3action.Warnings, result3 error) {
	fake.CreateAndUploadPackageByApplicationNameAndSpaceStub = nil
	fake.createAndUploadPackageByApplicationNameAndSpaceReturns = struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) CreateAndUploadPackageByApplicationNameAndSpaceReturnsOnCall(i int, result1 v3action.Package, result2 v3action.Warnings, result3 error) {
	fake.CreateAndUploadPackageByApplicationNameAndSpaceStub = nil
	if fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall == nil {
		fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 v3action.Package
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.createAndUploadPackageByApplicationNameAndSpaceReturnsOnCall[i] = struct {
		result1 v3action.Package
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) StagePackage(packageGUID string) (<-chan v3action.Build, <-chan v3action.Warnings, <-chan error) {
	fake.stagePackageMutex.Lock()
	ret, specificReturn := fake.stagePackageReturnsOnCall[len(fake.stagePackageArgsForCall)]
	fake.stagePackageArgsForCall = append(fake.stagePackageArgsForCall, struct {
		packageGUID string
	}{packageGUID})
	fake.recordInvocation("StagePackage", []interface{}{packageGUID})
	fake.stagePackageMutex.Unlock()
	if fake.StagePackageStub != nil {
		return fake.StagePackageStub(packageGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.stagePackageReturns.result1, fake.stagePackageReturns.result2, fake.stagePackageReturns.result3
}

func (fake *FakeV3PushActor) StagePackageCallCount() int {
	fake.stagePackageMutex.RLock()
	defer fake.stagePackageMutex.RUnlock()
	return len(fake.stagePackageArgsForCall)
}

func (fake *FakeV3PushActor) StagePackageArgsForCall(i int) string {
	fake.stagePackageMutex.RLock()
	defer fake.stagePackageMutex.RUnlock()
	return fake.stagePackageArgsForCall[i].packageGUID
}

func (fake *FakeV3PushActor) StagePackageReturns(result1 <-chan v3action.Build, result2 <-chan v3action.Warnings, result3 <-chan error) {
	fake.StagePackageStub = nil
	fake.stagePackageReturns = struct {
		result1 <-chan v3action.Build
		result2 <-chan v3action.Warnings
		result3 <-chan error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) StagePackageReturnsOnCall(i int, result1 <-chan v3action.Build, result2 <-chan v3action.Warnings, result3 <-chan error) {
	fake.StagePackageStub = nil
	if fake.stagePackageReturnsOnCall == nil {
		fake.stagePackageReturnsOnCall = make(map[int]struct {
			result1 <-chan v3action.Build
			result2 <-chan v3action.Warnings
			result3 <-chan error
		})
	}
	fake.stagePackageReturnsOnCall[i] = struct {
		result1 <-chan v3action.Build
		result2 <-chan v3action.Warnings
		result3 <-chan error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) GetStreamingLogsForApplicationByNameAndSpace(appName string, spaceGUID string, client v3action.NOAAClient) (<-chan *v3action.LogMessage, <-chan error, v3action.Warnings, error) {
	fake.getStreamingLogsForApplicationByNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.getStreamingLogsForApplicationByNameAndSpaceReturnsOnCall[len(fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall)]
	fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall = append(fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
		client    v3action.NOAAClient
	}{appName, spaceGUID, client})
	fake.recordInvocation("GetStreamingLogsForApplicationByNameAndSpace", []interface{}{appName, spaceGUID, client})
	fake.getStreamingLogsForApplicationByNameAndSpaceMutex.Unlock()
	if fake.GetStreamingLogsForApplicationByNameAndSpaceStub != nil {
		return fake.GetStreamingLogsForApplicationByNameAndSpaceStub(appName, spaceGUID, client)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3, ret.result4
	}
	return fake.getStreamingLogsForApplicationByNameAndSpaceReturns.result1, fake.getStreamingLogsForApplicationByNameAndSpaceReturns.result2, fake.getStreamingLogsForApplicationByNameAndSpaceReturns.result3, fake.getStreamingLogsForApplicationByNameAndSpaceReturns.result4
}

func (fake *FakeV3PushActor) GetStreamingLogsForApplicationByNameAndSpaceCallCount() int {
	fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RLock()
	defer fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RUnlock()
	return len(fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall)
}

func (fake *FakeV3PushActor) GetStreamingLogsForApplicationByNameAndSpaceArgsForCall(i int) (string, string, v3action.NOAAClient) {
	fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RLock()
	defer fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RUnlock()
	return fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall[i].appName, fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall[i].spaceGUID, fake.getStreamingLogsForApplicationByNameAndSpaceArgsForCall[i].client
}

func (fake *FakeV3PushActor) GetStreamingLogsForApplicationByNameAndSpaceReturns(result1 <-chan *v3action.LogMessage, result2 <-chan error, result3 v3action.Warnings, result4 error) {
	fake.GetStreamingLogsForApplicationByNameAndSpaceStub = nil
	fake.getStreamingLogsForApplicationByNameAndSpaceReturns = struct {
		result1 <-chan *v3action.LogMessage
		result2 <-chan error
		result3 v3action.Warnings
		result4 error
	}{result1, result2, result3, result4}
}

func (fake *FakeV3PushActor) GetStreamingLogsForApplicationByNameAndSpaceReturnsOnCall(i int, result1 <-chan *v3action.LogMessage, result2 <-chan error, result3 v3action.Warnings, result4 error) {
	fake.GetStreamingLogsForApplicationByNameAndSpaceStub = nil
	if fake.getStreamingLogsForApplicationByNameAndSpaceReturnsOnCall == nil {
		fake.getStreamingLogsForApplicationByNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 <-chan *v3action.LogMessage
			result2 <-chan error
			result3 v3action.Warnings
			result4 error
		})
	}
	fake.getStreamingLogsForApplicationByNameAndSpaceReturnsOnCall[i] = struct {
		result1 <-chan *v3action.LogMessage
		result2 <-chan error
		result3 v3action.Warnings
		result4 error
	}{result1, result2, result3, result4}
}

func (fake *FakeV3PushActor) SetApplicationDroplet(appName string, spaceGUID string, dropletGUID string) (v3action.Warnings, error) {
	fake.setApplicationDropletMutex.Lock()
	ret, specificReturn := fake.setApplicationDropletReturnsOnCall[len(fake.setApplicationDropletArgsForCall)]
	fake.setApplicationDropletArgsForCall = append(fake.setApplicationDropletArgsForCall, struct {
		appName     string
		spaceGUID   string
		dropletGUID string
	}{appName, spaceGUID, dropletGUID})
	fake.recordInvocation("SetApplicationDroplet", []interface{}{appName, spaceGUID, dropletGUID})
	fake.setApplicationDropletMutex.Unlock()
	if fake.SetApplicationDropletStub != nil {
		return fake.SetApplicationDropletStub(appName, spaceGUID, dropletGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.setApplicationDropletReturns.result1, fake.setApplicationDropletReturns.result2
}

func (fake *FakeV3PushActor) SetApplicationDropletCallCount() int {
	fake.setApplicationDropletMutex.RLock()
	defer fake.setApplicationDropletMutex.RUnlock()
	return len(fake.setApplicationDropletArgsForCall)
}

func (fake *FakeV3PushActor) SetApplicationDropletArgsForCall(i int) (string, string, string) {
	fake.setApplicationDropletMutex.RLock()
	defer fake.setApplicationDropletMutex.RUnlock()
	return fake.setApplicationDropletArgsForCall[i].appName, fake.setApplicationDropletArgsForCall[i].spaceGUID, fake.setApplicationDropletArgsForCall[i].dropletGUID
}

func (fake *FakeV3PushActor) SetApplicationDropletReturns(result1 v3action.Warnings, result2 error) {
	fake.SetApplicationDropletStub = nil
	fake.setApplicationDropletReturns = struct {
		result1 v3action.Warnings
		result2 error
	}{result1, result2}
}

func (fake *FakeV3PushActor) SetApplicationDropletReturnsOnCall(i int, result1 v3action.Warnings, result2 error) {
	fake.SetApplicationDropletStub = nil
	if fake.setApplicationDropletReturnsOnCall == nil {
		fake.setApplicationDropletReturnsOnCall = make(map[int]struct {
			result1 v3action.Warnings
			result2 error
		})
	}
	fake.setApplicationDropletReturnsOnCall[i] = struct {
		result1 v3action.Warnings
		result2 error
	}{result1, result2}
}

func (fake *FakeV3PushActor) StartApplication(appName string, spaceGUID string) (v3action.Application, v3action.Warnings, error) {
	fake.startApplicationMutex.Lock()
	ret, specificReturn := fake.startApplicationReturnsOnCall[len(fake.startApplicationArgsForCall)]
	fake.startApplicationArgsForCall = append(fake.startApplicationArgsForCall, struct {
		appName   string
		spaceGUID string
	}{appName, spaceGUID})
	fake.recordInvocation("StartApplication", []interface{}{appName, spaceGUID})
	fake.startApplicationMutex.Unlock()
	if fake.StartApplicationStub != nil {
		return fake.StartApplicationStub(appName, spaceGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.startApplicationReturns.result1, fake.startApplicationReturns.result2, fake.startApplicationReturns.result3
}

func (fake *FakeV3PushActor) StartApplicationCallCount() int {
	fake.startApplicationMutex.RLock()
	defer fake.startApplicationMutex.RUnlock()
	return len(fake.startApplicationArgsForCall)
}

func (fake *FakeV3PushActor) StartApplicationArgsForCall(i int) (string, string) {
	fake.startApplicationMutex.RLock()
	defer fake.startApplicationMutex.RUnlock()
	return fake.startApplicationArgsForCall[i].appName, fake.startApplicationArgsForCall[i].spaceGUID
}

func (fake *FakeV3PushActor) StartApplicationReturns(result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.StartApplicationStub = nil
	fake.startApplicationReturns = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) StartApplicationReturnsOnCall(i int, result1 v3action.Application, result2 v3action.Warnings, result3 error) {
	fake.StartApplicationStub = nil
	if fake.startApplicationReturnsOnCall == nil {
		fake.startApplicationReturnsOnCall = make(map[int]struct {
			result1 v3action.Application
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.startApplicationReturnsOnCall[i] = struct {
		result1 v3action.Application
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) GetApplicationSummaryByNameAndSpace(appName string, spaceGUID string) (v3action.ApplicationSummary, v3action.Warnings, error) {
	fake.getApplicationSummaryByNameAndSpaceMutex.Lock()
	ret, specificReturn := fake.getApplicationSummaryByNameAndSpaceReturnsOnCall[len(fake.getApplicationSummaryByNameAndSpaceArgsForCall)]
	fake.getApplicationSummaryByNameAndSpaceArgsForCall = append(fake.getApplicationSummaryByNameAndSpaceArgsForCall, struct {
		appName   string
		spaceGUID string
	}{appName, spaceGUID})
	fake.recordInvocation("GetApplicationSummaryByNameAndSpace", []interface{}{appName, spaceGUID})
	fake.getApplicationSummaryByNameAndSpaceMutex.Unlock()
	if fake.GetApplicationSummaryByNameAndSpaceStub != nil {
		return fake.GetApplicationSummaryByNameAndSpaceStub(appName, spaceGUID)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.getApplicationSummaryByNameAndSpaceReturns.result1, fake.getApplicationSummaryByNameAndSpaceReturns.result2, fake.getApplicationSummaryByNameAndSpaceReturns.result3
}

func (fake *FakeV3PushActor) GetApplicationSummaryByNameAndSpaceCallCount() int {
	fake.getApplicationSummaryByNameAndSpaceMutex.RLock()
	defer fake.getApplicationSummaryByNameAndSpaceMutex.RUnlock()
	return len(fake.getApplicationSummaryByNameAndSpaceArgsForCall)
}

func (fake *FakeV3PushActor) GetApplicationSummaryByNameAndSpaceArgsForCall(i int) (string, string) {
	fake.getApplicationSummaryByNameAndSpaceMutex.RLock()
	defer fake.getApplicationSummaryByNameAndSpaceMutex.RUnlock()
	return fake.getApplicationSummaryByNameAndSpaceArgsForCall[i].appName, fake.getApplicationSummaryByNameAndSpaceArgsForCall[i].spaceGUID
}

func (fake *FakeV3PushActor) GetApplicationSummaryByNameAndSpaceReturns(result1 v3action.ApplicationSummary, result2 v3action.Warnings, result3 error) {
	fake.GetApplicationSummaryByNameAndSpaceStub = nil
	fake.getApplicationSummaryByNameAndSpaceReturns = struct {
		result1 v3action.ApplicationSummary
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) GetApplicationSummaryByNameAndSpaceReturnsOnCall(i int, result1 v3action.ApplicationSummary, result2 v3action.Warnings, result3 error) {
	fake.GetApplicationSummaryByNameAndSpaceStub = nil
	if fake.getApplicationSummaryByNameAndSpaceReturnsOnCall == nil {
		fake.getApplicationSummaryByNameAndSpaceReturnsOnCall = make(map[int]struct {
			result1 v3action.ApplicationSummary
			result2 v3action.Warnings
			result3 error
		})
	}
	fake.getApplicationSummaryByNameAndSpaceReturnsOnCall[i] = struct {
		result1 v3action.ApplicationSummary
		result2 v3action.Warnings
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeV3PushActor) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.createApplicationByNameAndSpaceMutex.RLock()
	defer fake.createApplicationByNameAndSpaceMutex.RUnlock()
	fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RLock()
	defer fake.createAndUploadPackageByApplicationNameAndSpaceMutex.RUnlock()
	fake.stagePackageMutex.RLock()
	defer fake.stagePackageMutex.RUnlock()
	fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RLock()
	defer fake.getStreamingLogsForApplicationByNameAndSpaceMutex.RUnlock()
	fake.setApplicationDropletMutex.RLock()
	defer fake.setApplicationDropletMutex.RUnlock()
	fake.startApplicationMutex.RLock()
	defer fake.startApplicationMutex.RUnlock()
	fake.getApplicationSummaryByNameAndSpaceMutex.RLock()
	defer fake.getApplicationSummaryByNameAndSpaceMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeV3PushActor) recordInvocation(key string, args []interface{}) {
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

var _ v3.V3PushActor = new(FakeV3PushActor)
