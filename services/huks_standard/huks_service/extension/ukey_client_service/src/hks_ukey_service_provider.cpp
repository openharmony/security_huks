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

#include "hks_ukey_service_provider.h"

namespace OHOS {
namespace Security {
namespace Huks {

int32_t HksIpcServiceProviderRegister(const struct HksProcessInfo *processInfo,
    std::string &name, CppParamSet &paramSet)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->RegisterProvider(*processInfo, name, paramSet);
}

int32_t HksIpcServiceProviderUnRegister(const struct HksProcessInfo *processInfo, std::string &name,
    CppParamSet &paramSet)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    bool isDeath = false;
    return pluginManager->UnRegisterProvider(*processInfo, name, paramSet, isDeath);
}

int32_t HksIpcServiceOnCreateRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string &index,
    CppParamSet &paramSet, std::string &remoteHandleOut)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnCreateRemoteKeyHandle(*processInfo, index, paramSet, remoteHandleOut);
}

int32_t HksIpcServiceOnCloseRemoteKeyHandle(const struct HksProcessInfo *processInfo,
    std::string &index, CppParamSet &paramSet)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnCloseRemoteKeyHandle(*processInfo, index, paramSet);
}

int32_t HksIpcServiceOnAuthUkeyPin(const struct HksProcessInfo *processInfo, const std::string &index,
    CppParamSet &pinData, int32_t &authState, uint32_t &retryCnt)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnAuthUkeyPin(*processInfo, index, pinData, authState, retryCnt);
}

int32_t HksIpcServiceOnGetVerifyPinStatus(const struct HksProcessInfo *processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    return pluginManager->OnGetVerifyPinStatus(*processInfo, index, paramSet, state);
}

int32_t HksIpcServiceOnClearUkeyPinAuthStatus(const struct HksProcessInfo *processInfo, const std::string &index)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    int32_t ret = pluginManager->OnClearUkeyPinAuthStatus(*processInfo, index);
    return ret;
}

int32_t HksIpcServiceOnGetRemoteProperty(const HksProcessInfo *processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    int32_t ret = pluginManager->OnGetRemoteProperty(*processInfo, index, propertyId, paramSet, outParams);
    return ret;
}

int32_t HksIpcServiceOnExportCertificate(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certificatesOut)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnExportCertificate(*processInfo, index, paramSet, certificatesOut);
}

int32_t HksIpcServiceOnExportProviderAllCertificates(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certificatesOut)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnExportProviderAllCertificates(*processInfo, index, paramSet, certificatesOut);
}

}
}
}
