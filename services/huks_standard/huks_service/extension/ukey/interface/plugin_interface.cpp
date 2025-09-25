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

#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_remote_handle_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_template.h"
#include <string>
#include <vector>

namespace OHOS::Security::Huks {

__attribute__((visibility("default"))) int32_t HksExtPluginOnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerMgr == nullptr, HKS_ERROR_NULL_POINTER, "providerMgr is null");
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerMgr == nullptr, HKS_ERROR_NULL_POINTER, "providerMgr is null");
    auto ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnCreateRemoteIndex(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &index)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = HKS_SUCCESS;
    // TODO: handleMgr
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnOpemRemoteHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &handle)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    // handle is need to be set??
    (void)handle;
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->CreateRemoteHandle(index, paramSet);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnCloseRemoteHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->CloseRemoteHandle(index, paramSet);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnAuthUkeyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t& authState, uint32_t& retryCnt)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->RemoteVerifyPin(processInfo, index, paramSet, authState, retryCnt);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnGetUkeyPinAuthState(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &state)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->RemoteVerifyPinStatus(processInfo, index, paramSet, state);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnExportCerticate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->FindRemoteCertificate(index, paramSet, certsJson);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnExportProviderCerticates(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJsonArr)
{
    HKS_LOG_E("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->FindRemoteAllCertificate(index, paramSet, certsJsonArr);
    HKS_LOG_E("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

}