/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_log.h"

namespace OHOS {
namespace Security {
namespace Huks {

// ==================== HuksPluginLifeCycleMgr mock ====================

std::shared_ptr<HuksPluginLifeCycleMgr> HuksPluginLifeCycleMgr::GetInstanceWrapper()
{
    return HuksPluginLifeCycleMgr::GetInstance();
}

void HuksPluginLifeCycleMgr::ReleaseInstance()
{
    HuksPluginLifeCycleMgr::DestroyInstance();
}

int32_t HuksPluginLifeCycleMgr::RegisterProvider(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet,
    std::function<void(HksProcessInfo)> callback)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnUnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount)
{
    deleteCount = 1;
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnAuthUkeyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt)
{
    authState = 1;
    retryCnt = 0;
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    state = 1;
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnClearUkeyPinAuthStatus(const HksProcessInfo &processInfo,
    const std::string &index)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnGetRemoteProperty(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &propertyId, const CppParamSet &paramSet,
    CppParamSet &outParams)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnExportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson)
{
    certsJson = "[{\"purpose\":1,\"index\":\"idx\",\"cert\":\"MIIB\"}]";
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnExportProviderAllCertificates(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr)
{
    certsJsonArr = "[{\"purpose\":1,\"index\":\"idx\",\"cert\":\"MIIB\"}]";
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnImportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const struct HksExtCertInfo &certInfo, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnGenerateKey(const HksProcessInfo &processInfo,
    const std::string &resourceId, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnInitSession(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnUpdateSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    outData.assign(1, 0);
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnFinishSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    outData.assign(1, 0);
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnAbortSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnUnregisterAllObservers()
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnImportWrappedKey(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &wrappingKeyIndex, const CppParamSet &paramSet,
    const std::vector<uint8_t> &wrappedData)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLifeCycleMgr::OnExportPublicKey(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::vector<uint8_t> &outData)
{
    outData.assign(1, 0);
    return HKS_SUCCESS;
}

// ==================== HuksPluginLoader mock ====================

HuksPluginLoader::HuksPluginLoader() {}

HuksPluginLoader::~HuksPluginLoader() {}

std::shared_ptr<HuksPluginLoader> HuksPluginLoader::GetInstanceWrapper()
{
    return HuksPluginLoader::GetInstance();
}

void HuksPluginLoader::ReleaseInstance()
{
    HuksPluginLoader::DestroyInstance();
}

int32_t HuksPluginLoader::LoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::UnLoadPlugins(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    return HKS_SUCCESS;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
