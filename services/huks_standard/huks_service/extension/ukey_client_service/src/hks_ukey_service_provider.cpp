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
    HKS_LOG_E("got pluginManager instance");
    return pluginManager->RegisterProvider(*processInfo, name, paramSet);
}

int32_t HksIpcServiceProviderUnRegister(const struct HksProcessInfo *processInfo, std::string &name,
    CppParamSet &paramSet)
{
    auto pluginManager = HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    HKS_LOG_E("got pluginManager instance");
    return pluginManager->UnRegisterProvider(*processInfo, name, paramSet);
}

int32_t HksIpcServiceOnCreateRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string &index,
    CppParamSet &paramSet, std::string &remoteHandleOut)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    return libInterface->OnCreateRemoteKeyHandle(*processInfo, index, paramSet, remoteHandleOut);
}

int32_t HksIpcServiceOnCloseRemoteKeyHandle(const struct HksProcessInfo *processInfo,
    std::string &index, CppParamSet &paramSet)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    return libInterface->OnCloseRemoteKeyHandle(*processInfo, index, paramSet);
}

int32_t HksIpcServiceOnAuthUkeyPin(const struct HksProcessInfo *processInfo, const std::string &index,
    CppParamSet &pinData, int32_t &authState, uint32_t &retryCnt)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    return libInterface->OnAuthUkeyPin(*processInfo, index, pinData, authState, retryCnt);
}

int32_t HksIpcServiceOnGetVerifyPinStatus(const struct HksProcessInfo *processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");

    return libInterface->OnGetVerifyPinStatus(*processInfo, index, paramSet, state);
}

int32_t HksIpcServiceOnClearUkeyPinAuthStatus(const struct HksProcessInfo *processInfo, const std::string &index)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    int32_t ret = libInterface->OnClearUkeyPinAuthStatus(*processInfo, index);
    return ret;
}

int32_t HksIpcServiceOnGetRemoteProperty(const HksProcessInfo *processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    int32_t ret = libInterface->OnGetRemoteProperty(*processInfo, index, propertyId, paramSet, outParams);
    return ret;
}
    
int32_t HksIpcServiceOnListProviders(std::vector<uint8_t> &providersOut)
{
    return 0;
}

int32_t HksIpcServiceOnExportCertificate(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &cetificatesOut)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    return libInterface->OnExportCertificate(*processInfo, index, paramSet, cetificatesOut);
}

int32_t HksIpcServiceOnExportProviderAllCertificates(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &cetificatesOut)
{
    auto libInterface = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    HKS_LOG_E("got libInterface instance");
    return libInterface->OnExportProviderAllCertificates(*processInfo, index, paramSet, cetificatesOut);
}

int32_t HksIpcServiceOnFindRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string &index,
    CppParamSet &paramSet, std::string &remoteHandleOut)
{
    return 0;
}

}
}
}
