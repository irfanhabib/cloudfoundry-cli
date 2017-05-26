// Code generated by counterfeiter. DO NOT EDIT.
package commonfakes

import (
	"sync"

	"code.cloudfoundry.org/cli/actor/pluginaction"
	"code.cloudfoundry.org/cli/command/common"
	"code.cloudfoundry.org/cli/util/configv3"
)

type FakeInstallPluginActor struct {
	CreateExecutableCopyStub        func(path string, tempPluginDir string) (string, error)
	createExecutableCopyMutex       sync.RWMutex
	createExecutableCopyArgsForCall []struct {
		path          string
		tempPluginDir string
	}
	createExecutableCopyReturns struct {
		result1 string
		result2 error
	}
	createExecutableCopyReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	DownloadExecutableBinaryFromURLStub        func(url string, tempPluginDir string) (string, int64, error)
	downloadExecutableBinaryFromURLMutex       sync.RWMutex
	downloadExecutableBinaryFromURLArgsForCall []struct {
		url           string
		tempPluginDir string
	}
	downloadExecutableBinaryFromURLReturns struct {
		result1 string
		result2 int64
		result3 error
	}
	downloadExecutableBinaryFromURLReturnsOnCall map[int]struct {
		result1 string
		result2 int64
		result3 error
	}
	FileExistsStub        func(path string) bool
	fileExistsMutex       sync.RWMutex
	fileExistsArgsForCall []struct {
		path string
	}
	fileExistsReturns struct {
		result1 bool
	}
	fileExistsReturnsOnCall map[int]struct {
		result1 bool
	}
	GetAndValidatePluginStub        func(metadata pluginaction.PluginMetadata, commands pluginaction.CommandList, path string) (configv3.Plugin, error)
	getAndValidatePluginMutex       sync.RWMutex
	getAndValidatePluginArgsForCall []struct {
		metadata pluginaction.PluginMetadata
		commands pluginaction.CommandList
		path     string
	}
	getAndValidatePluginReturns struct {
		result1 configv3.Plugin
		result2 error
	}
	getAndValidatePluginReturnsOnCall map[int]struct {
		result1 configv3.Plugin
		result2 error
	}
	GetPlatformStringStub        func(runtimeGOOS string, runtimeGOARCH string) string
	getPlatformStringMutex       sync.RWMutex
	getPlatformStringArgsForCall []struct {
		runtimeGOOS   string
		runtimeGOARCH string
	}
	getPlatformStringReturns struct {
		result1 string
	}
	getPlatformStringReturnsOnCall map[int]struct {
		result1 string
	}
	GetPluginInfoFromRepositoryForPlatformStub        func(pluginName string, pluginRepo configv3.PluginRepository, platform string) (pluginaction.PluginInfo, error)
	getPluginInfoFromRepositoryForPlatformMutex       sync.RWMutex
	getPluginInfoFromRepositoryForPlatformArgsForCall []struct {
		pluginName string
		pluginRepo configv3.PluginRepository
		platform   string
	}
	getPluginInfoFromRepositoryForPlatformReturns struct {
		result1 pluginaction.PluginInfo
		result2 error
	}
	getPluginInfoFromRepositoryForPlatformReturnsOnCall map[int]struct {
		result1 pluginaction.PluginInfo
		result2 error
	}
	GetPluginInfoFromAllRepositoriesStub        func(pluginName string, pluginRepos []configv3.PluginRepository) (pluginaction.PluginInfo, error)
	getPluginInfoFromAllRepositoriesMutex       sync.RWMutex
	getPluginInfoFromAllRepositoriesArgsForCall []struct {
		pluginName  string
		pluginRepos []configv3.PluginRepository
	}
	getPluginInfoFromAllRepositoriesReturns struct {
		result1 pluginaction.PluginInfo
		result2 error
	}
	getPluginInfoFromAllRepositoriesReturnsOnCall map[int]struct {
		result1 pluginaction.PluginInfo
		result2 error
	}
	GetPluginRepositoryStub        func(repositoryName string) (configv3.PluginRepository, error)
	getPluginRepositoryMutex       sync.RWMutex
	getPluginRepositoryArgsForCall []struct {
		repositoryName string
	}
	getPluginRepositoryReturns struct {
		result1 configv3.PluginRepository
		result2 error
	}
	getPluginRepositoryReturnsOnCall map[int]struct {
		result1 configv3.PluginRepository
		result2 error
	}
	InstallPluginFromPathStub        func(path string, plugin configv3.Plugin) error
	installPluginFromPathMutex       sync.RWMutex
	installPluginFromPathArgsForCall []struct {
		path   string
		plugin configv3.Plugin
	}
	installPluginFromPathReturns struct {
		result1 error
	}
	installPluginFromPathReturnsOnCall map[int]struct {
		result1 error
	}
	IsPluginInstalledStub        func(pluginName string) bool
	isPluginInstalledMutex       sync.RWMutex
	isPluginInstalledArgsForCall []struct {
		pluginName string
	}
	isPluginInstalledReturns struct {
		result1 bool
	}
	isPluginInstalledReturnsOnCall map[int]struct {
		result1 bool
	}
	UninstallPluginStub        func(uninstaller pluginaction.PluginUninstaller, name string) error
	uninstallPluginMutex       sync.RWMutex
	uninstallPluginArgsForCall []struct {
		uninstaller pluginaction.PluginUninstaller
		name        string
	}
	uninstallPluginReturns struct {
		result1 error
	}
	uninstallPluginReturnsOnCall map[int]struct {
		result1 error
	}
	ValidateFileChecksumStub        func(path string, checksum string) bool
	validateFileChecksumMutex       sync.RWMutex
	validateFileChecksumArgsForCall []struct {
		path     string
		checksum string
	}
	validateFileChecksumReturns struct {
		result1 bool
	}
	validateFileChecksumReturnsOnCall map[int]struct {
		result1 bool
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeInstallPluginActor) CreateExecutableCopy(path string, tempPluginDir string) (string, error) {
	fake.createExecutableCopyMutex.Lock()
	ret, specificReturn := fake.createExecutableCopyReturnsOnCall[len(fake.createExecutableCopyArgsForCall)]
	fake.createExecutableCopyArgsForCall = append(fake.createExecutableCopyArgsForCall, struct {
		path          string
		tempPluginDir string
	}{path, tempPluginDir})
	fake.recordInvocation("CreateExecutableCopy", []interface{}{path, tempPluginDir})
	fake.createExecutableCopyMutex.Unlock()
	if fake.CreateExecutableCopyStub != nil {
		return fake.CreateExecutableCopyStub(path, tempPluginDir)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.createExecutableCopyReturns.result1, fake.createExecutableCopyReturns.result2
}

func (fake *FakeInstallPluginActor) CreateExecutableCopyCallCount() int {
	fake.createExecutableCopyMutex.RLock()
	defer fake.createExecutableCopyMutex.RUnlock()
	return len(fake.createExecutableCopyArgsForCall)
}

func (fake *FakeInstallPluginActor) CreateExecutableCopyArgsForCall(i int) (string, string) {
	fake.createExecutableCopyMutex.RLock()
	defer fake.createExecutableCopyMutex.RUnlock()
	return fake.createExecutableCopyArgsForCall[i].path, fake.createExecutableCopyArgsForCall[i].tempPluginDir
}

func (fake *FakeInstallPluginActor) CreateExecutableCopyReturns(result1 string, result2 error) {
	fake.CreateExecutableCopyStub = nil
	fake.createExecutableCopyReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) CreateExecutableCopyReturnsOnCall(i int, result1 string, result2 error) {
	fake.CreateExecutableCopyStub = nil
	if fake.createExecutableCopyReturnsOnCall == nil {
		fake.createExecutableCopyReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.createExecutableCopyReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) DownloadExecutableBinaryFromURL(url string, tempPluginDir string) (string, int64, error) {
	fake.downloadExecutableBinaryFromURLMutex.Lock()
	ret, specificReturn := fake.downloadExecutableBinaryFromURLReturnsOnCall[len(fake.downloadExecutableBinaryFromURLArgsForCall)]
	fake.downloadExecutableBinaryFromURLArgsForCall = append(fake.downloadExecutableBinaryFromURLArgsForCall, struct {
		url           string
		tempPluginDir string
	}{url, tempPluginDir})
	fake.recordInvocation("DownloadExecutableBinaryFromURL", []interface{}{url, tempPluginDir})
	fake.downloadExecutableBinaryFromURLMutex.Unlock()
	if fake.DownloadExecutableBinaryFromURLStub != nil {
		return fake.DownloadExecutableBinaryFromURLStub(url, tempPluginDir)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.downloadExecutableBinaryFromURLReturns.result1, fake.downloadExecutableBinaryFromURLReturns.result2, fake.downloadExecutableBinaryFromURLReturns.result3
}

func (fake *FakeInstallPluginActor) DownloadExecutableBinaryFromURLCallCount() int {
	fake.downloadExecutableBinaryFromURLMutex.RLock()
	defer fake.downloadExecutableBinaryFromURLMutex.RUnlock()
	return len(fake.downloadExecutableBinaryFromURLArgsForCall)
}

func (fake *FakeInstallPluginActor) DownloadExecutableBinaryFromURLArgsForCall(i int) (string, string) {
	fake.downloadExecutableBinaryFromURLMutex.RLock()
	defer fake.downloadExecutableBinaryFromURLMutex.RUnlock()
	return fake.downloadExecutableBinaryFromURLArgsForCall[i].url, fake.downloadExecutableBinaryFromURLArgsForCall[i].tempPluginDir
}

func (fake *FakeInstallPluginActor) DownloadExecutableBinaryFromURLReturns(result1 string, result2 int64, result3 error) {
	fake.DownloadExecutableBinaryFromURLStub = nil
	fake.downloadExecutableBinaryFromURLReturns = struct {
		result1 string
		result2 int64
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeInstallPluginActor) DownloadExecutableBinaryFromURLReturnsOnCall(i int, result1 string, result2 int64, result3 error) {
	fake.DownloadExecutableBinaryFromURLStub = nil
	if fake.downloadExecutableBinaryFromURLReturnsOnCall == nil {
		fake.downloadExecutableBinaryFromURLReturnsOnCall = make(map[int]struct {
			result1 string
			result2 int64
			result3 error
		})
	}
	fake.downloadExecutableBinaryFromURLReturnsOnCall[i] = struct {
		result1 string
		result2 int64
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeInstallPluginActor) FileExists(path string) bool {
	fake.fileExistsMutex.Lock()
	ret, specificReturn := fake.fileExistsReturnsOnCall[len(fake.fileExistsArgsForCall)]
	fake.fileExistsArgsForCall = append(fake.fileExistsArgsForCall, struct {
		path string
	}{path})
	fake.recordInvocation("FileExists", []interface{}{path})
	fake.fileExistsMutex.Unlock()
	if fake.FileExistsStub != nil {
		return fake.FileExistsStub(path)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.fileExistsReturns.result1
}

func (fake *FakeInstallPluginActor) FileExistsCallCount() int {
	fake.fileExistsMutex.RLock()
	defer fake.fileExistsMutex.RUnlock()
	return len(fake.fileExistsArgsForCall)
}

func (fake *FakeInstallPluginActor) FileExistsArgsForCall(i int) string {
	fake.fileExistsMutex.RLock()
	defer fake.fileExistsMutex.RUnlock()
	return fake.fileExistsArgsForCall[i].path
}

func (fake *FakeInstallPluginActor) FileExistsReturns(result1 bool) {
	fake.FileExistsStub = nil
	fake.fileExistsReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) FileExistsReturnsOnCall(i int, result1 bool) {
	fake.FileExistsStub = nil
	if fake.fileExistsReturnsOnCall == nil {
		fake.fileExistsReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.fileExistsReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) GetAndValidatePlugin(metadata pluginaction.PluginMetadata, commands pluginaction.CommandList, path string) (configv3.Plugin, error) {
	fake.getAndValidatePluginMutex.Lock()
	ret, specificReturn := fake.getAndValidatePluginReturnsOnCall[len(fake.getAndValidatePluginArgsForCall)]
	fake.getAndValidatePluginArgsForCall = append(fake.getAndValidatePluginArgsForCall, struct {
		metadata pluginaction.PluginMetadata
		commands pluginaction.CommandList
		path     string
	}{metadata, commands, path})
	fake.recordInvocation("GetAndValidatePlugin", []interface{}{metadata, commands, path})
	fake.getAndValidatePluginMutex.Unlock()
	if fake.GetAndValidatePluginStub != nil {
		return fake.GetAndValidatePluginStub(metadata, commands, path)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getAndValidatePluginReturns.result1, fake.getAndValidatePluginReturns.result2
}

func (fake *FakeInstallPluginActor) GetAndValidatePluginCallCount() int {
	fake.getAndValidatePluginMutex.RLock()
	defer fake.getAndValidatePluginMutex.RUnlock()
	return len(fake.getAndValidatePluginArgsForCall)
}

func (fake *FakeInstallPluginActor) GetAndValidatePluginArgsForCall(i int) (pluginaction.PluginMetadata, pluginaction.CommandList, string) {
	fake.getAndValidatePluginMutex.RLock()
	defer fake.getAndValidatePluginMutex.RUnlock()
	return fake.getAndValidatePluginArgsForCall[i].metadata, fake.getAndValidatePluginArgsForCall[i].commands, fake.getAndValidatePluginArgsForCall[i].path
}

func (fake *FakeInstallPluginActor) GetAndValidatePluginReturns(result1 configv3.Plugin, result2 error) {
	fake.GetAndValidatePluginStub = nil
	fake.getAndValidatePluginReturns = struct {
		result1 configv3.Plugin
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetAndValidatePluginReturnsOnCall(i int, result1 configv3.Plugin, result2 error) {
	fake.GetAndValidatePluginStub = nil
	if fake.getAndValidatePluginReturnsOnCall == nil {
		fake.getAndValidatePluginReturnsOnCall = make(map[int]struct {
			result1 configv3.Plugin
			result2 error
		})
	}
	fake.getAndValidatePluginReturnsOnCall[i] = struct {
		result1 configv3.Plugin
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPlatformString(runtimeGOOS string, runtimeGOARCH string) string {
	fake.getPlatformStringMutex.Lock()
	ret, specificReturn := fake.getPlatformStringReturnsOnCall[len(fake.getPlatformStringArgsForCall)]
	fake.getPlatformStringArgsForCall = append(fake.getPlatformStringArgsForCall, struct {
		runtimeGOOS   string
		runtimeGOARCH string
	}{runtimeGOOS, runtimeGOARCH})
	fake.recordInvocation("GetPlatformString", []interface{}{runtimeGOOS, runtimeGOARCH})
	fake.getPlatformStringMutex.Unlock()
	if fake.GetPlatformStringStub != nil {
		return fake.GetPlatformStringStub(runtimeGOOS, runtimeGOARCH)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.getPlatformStringReturns.result1
}

func (fake *FakeInstallPluginActor) GetPlatformStringCallCount() int {
	fake.getPlatformStringMutex.RLock()
	defer fake.getPlatformStringMutex.RUnlock()
	return len(fake.getPlatformStringArgsForCall)
}

func (fake *FakeInstallPluginActor) GetPlatformStringArgsForCall(i int) (string, string) {
	fake.getPlatformStringMutex.RLock()
	defer fake.getPlatformStringMutex.RUnlock()
	return fake.getPlatformStringArgsForCall[i].runtimeGOOS, fake.getPlatformStringArgsForCall[i].runtimeGOARCH
}

func (fake *FakeInstallPluginActor) GetPlatformStringReturns(result1 string) {
	fake.GetPlatformStringStub = nil
	fake.getPlatformStringReturns = struct {
		result1 string
	}{result1}
}

func (fake *FakeInstallPluginActor) GetPlatformStringReturnsOnCall(i int, result1 string) {
	fake.GetPlatformStringStub = nil
	if fake.getPlatformStringReturnsOnCall == nil {
		fake.getPlatformStringReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.getPlatformStringReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromRepositoryForPlatform(pluginName string, pluginRepo configv3.PluginRepository, platform string) (pluginaction.PluginInfo, error) {
	fake.getPluginInfoFromRepositoryForPlatformMutex.Lock()
	ret, specificReturn := fake.getPluginInfoFromRepositoryForPlatformReturnsOnCall[len(fake.getPluginInfoFromRepositoryForPlatformArgsForCall)]
	fake.getPluginInfoFromRepositoryForPlatformArgsForCall = append(fake.getPluginInfoFromRepositoryForPlatformArgsForCall, struct {
		pluginName string
		pluginRepo configv3.PluginRepository
		platform   string
	}{pluginName, pluginRepo, platform})
	fake.recordInvocation("GetPluginInfoFromRepositoryForPlatform", []interface{}{pluginName, pluginRepo, platform})
	fake.getPluginInfoFromRepositoryForPlatformMutex.Unlock()
	if fake.GetPluginInfoFromRepositoryForPlatformStub != nil {
		return fake.GetPluginInfoFromRepositoryForPlatformStub(pluginName, pluginRepo, platform)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getPluginInfoFromRepositoryForPlatformReturns.result1, fake.getPluginInfoFromRepositoryForPlatformReturns.result2
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromRepositoryForPlatformCallCount() int {
	fake.getPluginInfoFromRepositoryForPlatformMutex.RLock()
	defer fake.getPluginInfoFromRepositoryForPlatformMutex.RUnlock()
	return len(fake.getPluginInfoFromRepositoryForPlatformArgsForCall)
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromRepositoryForPlatformArgsForCall(i int) (string, configv3.PluginRepository, string) {
	fake.getPluginInfoFromRepositoryForPlatformMutex.RLock()
	defer fake.getPluginInfoFromRepositoryForPlatformMutex.RUnlock()
	return fake.getPluginInfoFromRepositoryForPlatformArgsForCall[i].pluginName, fake.getPluginInfoFromRepositoryForPlatformArgsForCall[i].pluginRepo, fake.getPluginInfoFromRepositoryForPlatformArgsForCall[i].platform
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromRepositoryForPlatformReturns(result1 pluginaction.PluginInfo, result2 error) {
	fake.GetPluginInfoFromRepositoryForPlatformStub = nil
	fake.getPluginInfoFromRepositoryForPlatformReturns = struct {
		result1 pluginaction.PluginInfo
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromRepositoryForPlatformReturnsOnCall(i int, result1 pluginaction.PluginInfo, result2 error) {
	fake.GetPluginInfoFromRepositoryForPlatformStub = nil
	if fake.getPluginInfoFromRepositoryForPlatformReturnsOnCall == nil {
		fake.getPluginInfoFromRepositoryForPlatformReturnsOnCall = make(map[int]struct {
			result1 pluginaction.PluginInfo
			result2 error
		})
	}
	fake.getPluginInfoFromRepositoryForPlatformReturnsOnCall[i] = struct {
		result1 pluginaction.PluginInfo
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromAllRepositories(pluginName string, pluginRepos []configv3.PluginRepository) (pluginaction.PluginInfo, error) {
	var pluginReposCopy []configv3.PluginRepository
	if pluginRepos != nil {
		pluginReposCopy = make([]configv3.PluginRepository, len(pluginRepos))
		copy(pluginReposCopy, pluginRepos)
	}
	fake.getPluginInfoFromAllRepositoriesMutex.Lock()
	ret, specificReturn := fake.getPluginInfoFromAllRepositoriesReturnsOnCall[len(fake.getPluginInfoFromAllRepositoriesArgsForCall)]
	fake.getPluginInfoFromAllRepositoriesArgsForCall = append(fake.getPluginInfoFromAllRepositoriesArgsForCall, struct {
		pluginName  string
		pluginRepos []configv3.PluginRepository
	}{pluginName, pluginReposCopy})
	fake.recordInvocation("GetPluginInfoFromAllRepositories", []interface{}{pluginName, pluginReposCopy})
	fake.getPluginInfoFromAllRepositoriesMutex.Unlock()
	if fake.GetPluginInfoFromAllRepositoriesStub != nil {
		return fake.GetPluginInfoFromAllRepositoriesStub(pluginName, pluginRepos)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getPluginInfoFromAllRepositoriesReturns.result1, fake.getPluginInfoFromAllRepositoriesReturns.result2
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromAllRepositoriesCallCount() int {
	fake.getPluginInfoFromAllRepositoriesMutex.RLock()
	defer fake.getPluginInfoFromAllRepositoriesMutex.RUnlock()
	return len(fake.getPluginInfoFromAllRepositoriesArgsForCall)
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromAllRepositoriesArgsForCall(i int) (string, []configv3.PluginRepository) {
	fake.getPluginInfoFromAllRepositoriesMutex.RLock()
	defer fake.getPluginInfoFromAllRepositoriesMutex.RUnlock()
	return fake.getPluginInfoFromAllRepositoriesArgsForCall[i].pluginName, fake.getPluginInfoFromAllRepositoriesArgsForCall[i].pluginRepos
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromAllRepositoriesReturns(result1 pluginaction.PluginInfo, result2 error) {
	fake.GetPluginInfoFromAllRepositoriesStub = nil
	fake.getPluginInfoFromAllRepositoriesReturns = struct {
		result1 pluginaction.PluginInfo
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPluginInfoFromAllRepositoriesReturnsOnCall(i int, result1 pluginaction.PluginInfo, result2 error) {
	fake.GetPluginInfoFromAllRepositoriesStub = nil
	if fake.getPluginInfoFromAllRepositoriesReturnsOnCall == nil {
		fake.getPluginInfoFromAllRepositoriesReturnsOnCall = make(map[int]struct {
			result1 pluginaction.PluginInfo
			result2 error
		})
	}
	fake.getPluginInfoFromAllRepositoriesReturnsOnCall[i] = struct {
		result1 pluginaction.PluginInfo
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPluginRepository(repositoryName string) (configv3.PluginRepository, error) {
	fake.getPluginRepositoryMutex.Lock()
	ret, specificReturn := fake.getPluginRepositoryReturnsOnCall[len(fake.getPluginRepositoryArgsForCall)]
	fake.getPluginRepositoryArgsForCall = append(fake.getPluginRepositoryArgsForCall, struct {
		repositoryName string
	}{repositoryName})
	fake.recordInvocation("GetPluginRepository", []interface{}{repositoryName})
	fake.getPluginRepositoryMutex.Unlock()
	if fake.GetPluginRepositoryStub != nil {
		return fake.GetPluginRepositoryStub(repositoryName)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getPluginRepositoryReturns.result1, fake.getPluginRepositoryReturns.result2
}

func (fake *FakeInstallPluginActor) GetPluginRepositoryCallCount() int {
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	return len(fake.getPluginRepositoryArgsForCall)
}

func (fake *FakeInstallPluginActor) GetPluginRepositoryArgsForCall(i int) string {
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	return fake.getPluginRepositoryArgsForCall[i].repositoryName
}

func (fake *FakeInstallPluginActor) GetPluginRepositoryReturns(result1 configv3.PluginRepository, result2 error) {
	fake.GetPluginRepositoryStub = nil
	fake.getPluginRepositoryReturns = struct {
		result1 configv3.PluginRepository
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) GetPluginRepositoryReturnsOnCall(i int, result1 configv3.PluginRepository, result2 error) {
	fake.GetPluginRepositoryStub = nil
	if fake.getPluginRepositoryReturnsOnCall == nil {
		fake.getPluginRepositoryReturnsOnCall = make(map[int]struct {
			result1 configv3.PluginRepository
			result2 error
		})
	}
	fake.getPluginRepositoryReturnsOnCall[i] = struct {
		result1 configv3.PluginRepository
		result2 error
	}{result1, result2}
}

func (fake *FakeInstallPluginActor) InstallPluginFromPath(path string, plugin configv3.Plugin) error {
	fake.installPluginFromPathMutex.Lock()
	ret, specificReturn := fake.installPluginFromPathReturnsOnCall[len(fake.installPluginFromPathArgsForCall)]
	fake.installPluginFromPathArgsForCall = append(fake.installPluginFromPathArgsForCall, struct {
		path   string
		plugin configv3.Plugin
	}{path, plugin})
	fake.recordInvocation("InstallPluginFromPath", []interface{}{path, plugin})
	fake.installPluginFromPathMutex.Unlock()
	if fake.InstallPluginFromPathStub != nil {
		return fake.InstallPluginFromPathStub(path, plugin)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.installPluginFromPathReturns.result1
}

func (fake *FakeInstallPluginActor) InstallPluginFromPathCallCount() int {
	fake.installPluginFromPathMutex.RLock()
	defer fake.installPluginFromPathMutex.RUnlock()
	return len(fake.installPluginFromPathArgsForCall)
}

func (fake *FakeInstallPluginActor) InstallPluginFromPathArgsForCall(i int) (string, configv3.Plugin) {
	fake.installPluginFromPathMutex.RLock()
	defer fake.installPluginFromPathMutex.RUnlock()
	return fake.installPluginFromPathArgsForCall[i].path, fake.installPluginFromPathArgsForCall[i].plugin
}

func (fake *FakeInstallPluginActor) InstallPluginFromPathReturns(result1 error) {
	fake.InstallPluginFromPathStub = nil
	fake.installPluginFromPathReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeInstallPluginActor) InstallPluginFromPathReturnsOnCall(i int, result1 error) {
	fake.InstallPluginFromPathStub = nil
	if fake.installPluginFromPathReturnsOnCall == nil {
		fake.installPluginFromPathReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.installPluginFromPathReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeInstallPluginActor) IsPluginInstalled(pluginName string) bool {
	fake.isPluginInstalledMutex.Lock()
	ret, specificReturn := fake.isPluginInstalledReturnsOnCall[len(fake.isPluginInstalledArgsForCall)]
	fake.isPluginInstalledArgsForCall = append(fake.isPluginInstalledArgsForCall, struct {
		pluginName string
	}{pluginName})
	fake.recordInvocation("IsPluginInstalled", []interface{}{pluginName})
	fake.isPluginInstalledMutex.Unlock()
	if fake.IsPluginInstalledStub != nil {
		return fake.IsPluginInstalledStub(pluginName)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.isPluginInstalledReturns.result1
}

func (fake *FakeInstallPluginActor) IsPluginInstalledCallCount() int {
	fake.isPluginInstalledMutex.RLock()
	defer fake.isPluginInstalledMutex.RUnlock()
	return len(fake.isPluginInstalledArgsForCall)
}

func (fake *FakeInstallPluginActor) IsPluginInstalledArgsForCall(i int) string {
	fake.isPluginInstalledMutex.RLock()
	defer fake.isPluginInstalledMutex.RUnlock()
	return fake.isPluginInstalledArgsForCall[i].pluginName
}

func (fake *FakeInstallPluginActor) IsPluginInstalledReturns(result1 bool) {
	fake.IsPluginInstalledStub = nil
	fake.isPluginInstalledReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) IsPluginInstalledReturnsOnCall(i int, result1 bool) {
	fake.IsPluginInstalledStub = nil
	if fake.isPluginInstalledReturnsOnCall == nil {
		fake.isPluginInstalledReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isPluginInstalledReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) UninstallPlugin(uninstaller pluginaction.PluginUninstaller, name string) error {
	fake.uninstallPluginMutex.Lock()
	ret, specificReturn := fake.uninstallPluginReturnsOnCall[len(fake.uninstallPluginArgsForCall)]
	fake.uninstallPluginArgsForCall = append(fake.uninstallPluginArgsForCall, struct {
		uninstaller pluginaction.PluginUninstaller
		name        string
	}{uninstaller, name})
	fake.recordInvocation("UninstallPlugin", []interface{}{uninstaller, name})
	fake.uninstallPluginMutex.Unlock()
	if fake.UninstallPluginStub != nil {
		return fake.UninstallPluginStub(uninstaller, name)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.uninstallPluginReturns.result1
}

func (fake *FakeInstallPluginActor) UninstallPluginCallCount() int {
	fake.uninstallPluginMutex.RLock()
	defer fake.uninstallPluginMutex.RUnlock()
	return len(fake.uninstallPluginArgsForCall)
}

func (fake *FakeInstallPluginActor) UninstallPluginArgsForCall(i int) (pluginaction.PluginUninstaller, string) {
	fake.uninstallPluginMutex.RLock()
	defer fake.uninstallPluginMutex.RUnlock()
	return fake.uninstallPluginArgsForCall[i].uninstaller, fake.uninstallPluginArgsForCall[i].name
}

func (fake *FakeInstallPluginActor) UninstallPluginReturns(result1 error) {
	fake.UninstallPluginStub = nil
	fake.uninstallPluginReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeInstallPluginActor) UninstallPluginReturnsOnCall(i int, result1 error) {
	fake.UninstallPluginStub = nil
	if fake.uninstallPluginReturnsOnCall == nil {
		fake.uninstallPluginReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.uninstallPluginReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeInstallPluginActor) ValidateFileChecksum(path string, checksum string) bool {
	fake.validateFileChecksumMutex.Lock()
	ret, specificReturn := fake.validateFileChecksumReturnsOnCall[len(fake.validateFileChecksumArgsForCall)]
	fake.validateFileChecksumArgsForCall = append(fake.validateFileChecksumArgsForCall, struct {
		path     string
		checksum string
	}{path, checksum})
	fake.recordInvocation("ValidateFileChecksum", []interface{}{path, checksum})
	fake.validateFileChecksumMutex.Unlock()
	if fake.ValidateFileChecksumStub != nil {
		return fake.ValidateFileChecksumStub(path, checksum)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.validateFileChecksumReturns.result1
}

func (fake *FakeInstallPluginActor) ValidateFileChecksumCallCount() int {
	fake.validateFileChecksumMutex.RLock()
	defer fake.validateFileChecksumMutex.RUnlock()
	return len(fake.validateFileChecksumArgsForCall)
}

func (fake *FakeInstallPluginActor) ValidateFileChecksumArgsForCall(i int) (string, string) {
	fake.validateFileChecksumMutex.RLock()
	defer fake.validateFileChecksumMutex.RUnlock()
	return fake.validateFileChecksumArgsForCall[i].path, fake.validateFileChecksumArgsForCall[i].checksum
}

func (fake *FakeInstallPluginActor) ValidateFileChecksumReturns(result1 bool) {
	fake.ValidateFileChecksumStub = nil
	fake.validateFileChecksumReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) ValidateFileChecksumReturnsOnCall(i int, result1 bool) {
	fake.ValidateFileChecksumStub = nil
	if fake.validateFileChecksumReturnsOnCall == nil {
		fake.validateFileChecksumReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.validateFileChecksumReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *FakeInstallPluginActor) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.createExecutableCopyMutex.RLock()
	defer fake.createExecutableCopyMutex.RUnlock()
	fake.downloadExecutableBinaryFromURLMutex.RLock()
	defer fake.downloadExecutableBinaryFromURLMutex.RUnlock()
	fake.fileExistsMutex.RLock()
	defer fake.fileExistsMutex.RUnlock()
	fake.getAndValidatePluginMutex.RLock()
	defer fake.getAndValidatePluginMutex.RUnlock()
	fake.getPlatformStringMutex.RLock()
	defer fake.getPlatformStringMutex.RUnlock()
	fake.getPluginInfoFromRepositoryForPlatformMutex.RLock()
	defer fake.getPluginInfoFromRepositoryForPlatformMutex.RUnlock()
	fake.getPluginInfoFromAllRepositoriesMutex.RLock()
	defer fake.getPluginInfoFromAllRepositoriesMutex.RUnlock()
	fake.getPluginRepositoryMutex.RLock()
	defer fake.getPluginRepositoryMutex.RUnlock()
	fake.installPluginFromPathMutex.RLock()
	defer fake.installPluginFromPathMutex.RUnlock()
	fake.isPluginInstalledMutex.RLock()
	defer fake.isPluginInstalledMutex.RUnlock()
	fake.uninstallPluginMutex.RLock()
	defer fake.uninstallPluginMutex.RUnlock()
	fake.validateFileChecksumMutex.RLock()
	defer fake.validateFileChecksumMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeInstallPluginActor) recordInvocation(key string, args []interface{}) {
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

var _ common.InstallPluginActor = new(FakeInstallPluginActor)
