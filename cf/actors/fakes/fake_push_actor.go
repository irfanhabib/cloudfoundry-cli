// This file was generated by counterfeiter
package fakes

import (
	"os"
	"sync"

	"github.com/cloudfoundry/cli/cf/actors"
	"github.com/cloudfoundry/cli/cf/api/resources"
)

type FakePushActor struct {
	UploadAppStub        func(appGuid string, zipFile *os.File, presentFiles []resources.AppFileResource) error
	uploadAppMutex       sync.RWMutex
	uploadAppArgsForCall []struct {
		appGuid      string
		zipFile      *os.File
		presentFiles []resources.AppFileResource
	}
	uploadAppReturns struct {
		result1 error
	}
	PopulateFileModeStub        func(appDir string, presentFiles []resources.AppFileResource) ([]resources.AppFileResource, error)
	populateFileModeMutex       sync.RWMutex
	populateFileModeArgsForCall []struct {
		appDir       string
		presentFiles []resources.AppFileResource
	}
	populateFileModeReturns struct {
		result1 []resources.AppFileResource
		result2 error
	}
	ProcessPathStub        func(dirOrZipFile string, f func(string)) error
	processPathMutex       sync.RWMutex
	processPathArgsForCall []struct {
		dirOrZipFile string
		f            func(string)
	}
	processPathReturns struct {
		result1 error
	}
	GatherFilesStub        func(appDir string, uploadDir string) ([]resources.AppFileResource, bool, error)
	gatherFilesMutex       sync.RWMutex
	gatherFilesArgsForCall []struct {
		appDir    string
		uploadDir string
	}
	gatherFilesReturns struct {
		result1 []resources.AppFileResource
		result2 bool
		result3 error
	}
}

func (fake *FakePushActor) UploadApp(appGuid string, zipFile *os.File, presentFiles []resources.AppFileResource) error {
	fake.uploadAppMutex.Lock()
	fake.uploadAppArgsForCall = append(fake.uploadAppArgsForCall, struct {
		appGuid      string
		zipFile      *os.File
		presentFiles []resources.AppFileResource
	}{appGuid, zipFile, presentFiles})
	fake.uploadAppMutex.Unlock()
	if fake.UploadAppStub != nil {
		return fake.UploadAppStub(appGuid, zipFile, presentFiles)
	} else {
		return fake.uploadAppReturns.result1
	}
}

func (fake *FakePushActor) UploadAppCallCount() int {
	fake.uploadAppMutex.RLock()
	defer fake.uploadAppMutex.RUnlock()
	return len(fake.uploadAppArgsForCall)
}

func (fake *FakePushActor) UploadAppArgsForCall(i int) (string, *os.File, []resources.AppFileResource) {
	fake.uploadAppMutex.RLock()
	defer fake.uploadAppMutex.RUnlock()
	return fake.uploadAppArgsForCall[i].appGuid, fake.uploadAppArgsForCall[i].zipFile, fake.uploadAppArgsForCall[i].presentFiles
}

func (fake *FakePushActor) UploadAppReturns(result1 error) {
	fake.UploadAppStub = nil
	fake.uploadAppReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakePushActor) PopulateFileMode(appDir string, presentFiles []resources.AppFileResource) ([]resources.AppFileResource, error) {
	fake.populateFileModeMutex.Lock()
	fake.populateFileModeArgsForCall = append(fake.populateFileModeArgsForCall, struct {
		appDir       string
		presentFiles []resources.AppFileResource
	}{appDir, presentFiles})
	fake.populateFileModeMutex.Unlock()
	if fake.PopulateFileModeStub != nil {
		return fake.PopulateFileModeStub(appDir, presentFiles)
	} else {
		return fake.populateFileModeReturns.result1, fake.populateFileModeReturns.result2
	}
}

func (fake *FakePushActor) PopulateFileModeCallCount() int {
	fake.populateFileModeMutex.RLock()
	defer fake.populateFileModeMutex.RUnlock()
	return len(fake.populateFileModeArgsForCall)
}

func (fake *FakePushActor) PopulateFileModeArgsForCall(i int) (string, []resources.AppFileResource) {
	fake.populateFileModeMutex.RLock()
	defer fake.populateFileModeMutex.RUnlock()
	return fake.populateFileModeArgsForCall[i].appDir, fake.populateFileModeArgsForCall[i].presentFiles
}

func (fake *FakePushActor) PopulateFileModeReturns(result1 []resources.AppFileResource, result2 error) {
	fake.PopulateFileModeStub = nil
	fake.populateFileModeReturns = struct {
		result1 []resources.AppFileResource
		result2 error
	}{result1, result2}
}

func (fake *FakePushActor) ProcessPath(dirOrZipFile string, f func(string)) error {
	fake.processPathMutex.Lock()
	fake.processPathArgsForCall = append(fake.processPathArgsForCall, struct {
		dirOrZipFile string
		f            func(string)
	}{dirOrZipFile, f})
	fake.processPathMutex.Unlock()
	if fake.ProcessPathStub != nil {
		return fake.ProcessPathStub(dirOrZipFile, f)
	} else {
		return fake.processPathReturns.result1
	}
}

func (fake *FakePushActor) ProcessPathCallCount() int {
	fake.processPathMutex.RLock()
	defer fake.processPathMutex.RUnlock()
	return len(fake.processPathArgsForCall)
}

func (fake *FakePushActor) ProcessPathArgsForCall(i int) (string, func(string)) {
	fake.processPathMutex.RLock()
	defer fake.processPathMutex.RUnlock()
	return fake.processPathArgsForCall[i].dirOrZipFile, fake.processPathArgsForCall[i].f
}

func (fake *FakePushActor) ProcessPathReturns(result1 error) {
	fake.ProcessPathStub = nil
	fake.processPathReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakePushActor) GatherFiles(appDir string, uploadDir string) ([]resources.AppFileResource, bool, error) {
	fake.gatherFilesMutex.Lock()
	fake.gatherFilesArgsForCall = append(fake.gatherFilesArgsForCall, struct {
		appDir    string
		uploadDir string
	}{appDir, uploadDir})
	fake.gatherFilesMutex.Unlock()
	if fake.GatherFilesStub != nil {
		return fake.GatherFilesStub(appDir, uploadDir)
	} else {
		return fake.gatherFilesReturns.result1, fake.gatherFilesReturns.result2, fake.gatherFilesReturns.result3
	}
}

func (fake *FakePushActor) GatherFilesCallCount() int {
	fake.gatherFilesMutex.RLock()
	defer fake.gatherFilesMutex.RUnlock()
	return len(fake.gatherFilesArgsForCall)
}

func (fake *FakePushActor) GatherFilesArgsForCall(i int) (string, string) {
	fake.gatherFilesMutex.RLock()
	defer fake.gatherFilesMutex.RUnlock()
	return fake.gatherFilesArgsForCall[i].appDir, fake.gatherFilesArgsForCall[i].uploadDir
}

func (fake *FakePushActor) GatherFilesReturns(result1 []resources.AppFileResource, result2 bool, result3 error) {
	fake.GatherFilesStub = nil
	fake.gatherFilesReturns = struct {
		result1 []resources.AppFileResource
		result2 bool
		result3 error
	}{result1, result2, result3}
}

var _ actors.PushActor = new(FakePushActor)
