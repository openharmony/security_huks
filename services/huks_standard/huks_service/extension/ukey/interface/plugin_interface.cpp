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
#include "hks_session_manger.h"
#include "hks_cpp_paramset.h"
#include "hks_template.h"
#include <string>
#include <vector>

#include "app_observer.h"

namespace OHOS::Security::Huks {

static bool CheckParamPurpose(const CppParamSet &paramSet)
{
    auto paramPurpose = paramSet.GetParam<HKS_TAG_PURPOSE>();
    HKS_IF_NOT_TRUE_RETURN(paramPurpose.first == HKS_SUCCESS, false);
    uint32_t purpose = paramPurpose.second;
    return purpose > 0 && (purpose & (purpose - 1)) == 0 && (purpose & ~0x1FF) == 0;
}

static void RegisterObserverForProcess(const HksProcessInfo &processInfo, const CppParamSet &paramSet)
{
    int32_t ret = OHOS::Security::Huks::HksAppObserverManager::GetInstance().RegisterObserver(processInfo, paramSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "Failed to register observer for uid: %{public}u, ret=%{public}d",
        processInfo.uidInt, ret);
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(bool)> callback)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerMgr == nullptr, HKS_ERROR_NULL_POINTER, "providerMgr is null");
    auto ret = providerMgr->OnRegisterProvider(processInfo, providerName, paramSet, callback);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    int32_t ret = HKS_SUCCESS;
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    handleMgr->ClearAuthState(processInfo);
    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    if (abilityName.first == HKS_SUCCESS) {
        std::string str(abilityName.second.begin(), abilityName.second.end());
        ret = handleMgr->ClearRemoteHandleMap(providerName, str, processInfo.uidInt);
    } else {
        ret = handleMgr->ClearRemoteHandleMap(providerName, "", processInfo.uidInt);
    }
    HKS_IF_TRUE_LOGE(ret != HKS_SUCCESS, "clear index map fail");

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_NULL_LOGE_RETURN(sessionMgr, HKS_ERROR_NULL_POINTER, "sessionMgr is null")
    auto retBool = sessionMgr->HksClearHandle(processInfo, paramSet);
    HKS_IF_TRUE_LOGE(!retBool, "clear handle map fail");

    auto providerMgr = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerMgr == nullptr, HKS_ERROR_NULL_POINTER, "providerMgr is null");
    ret = providerMgr->OnUnRegisterProvider(processInfo, providerName, paramSet, isdeath);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    HKS_IF_TRUE_RETURN(ret != HKS_SUCCESS, ret)
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnCreateRemoteIndex(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &index)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnOpemRemoteHandle(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet, std::string &handle)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    CppParamSet paramSetWithUid(paramSet);
    auto uidParam = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    if (uidParam.first == HKS_SUCCESS) {
        HKS_IF_NOT_TRUE_RETURN(uidParam.second == processInfo.uidInt, HKS_ERROR_INVALID_ARGUMENT);
    } else {
        struct HksParam uid = {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = processInfo.uidInt};
        HKS_IF_TRUE_LOGE_RETURN(!paramSetWithUid.AddParams({uid}), HKS_ERROR_INVALID_ARGUMENT,
            "AddUidToParamset fail")
    }
    (void)handle;
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->CreateRemoteHandle(processInfo, index, paramSetWithUid);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnCloseRemoteHandle(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->CloseRemoteHandle(processInfo, index, paramSet);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnAuthUkeyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto uid = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    if (uid.first == HKS_SUCCESS) {
        HksProcessInfo processInfoTmp = {};
        processInfoTmp.uidInt = uid.second;
        RegisterObserverForProcess(processInfoTmp, paramSet);
    }
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->RemoteVerifyPin(processInfo, index, paramSet, authState, retryCnt);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnGetUkeyPinAuthState(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->RemoteVerifyPinStatus(processInfo, index, paramSet, state);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnExportCerticate(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet, std::string &certsJson)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->FindRemoteCertificate(index, paramSet, certsJson);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnExportProviderCerticates(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &certsJsonArr)
{
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    auto ret = handleMgr->FindRemoteAllCertificate(processInfo, providerName, paramSet, certsJsonArr);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnInitSession(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    HKS_IF_NOT_TRUE_LOGE_RETURN(CheckParamPurpose(paramSet), HKS_ERROR_INVALID_PURPOSE,
        "InitSession purpose check failed")
    RegisterObserverForProcess(processInfo, paramSet);
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(sessionMgr == nullptr, HKS_ERROR_NULL_POINTER, "sessionMgr is null");
    ret = sessionMgr->ExtensionInitSession(processInfo, index, paramSet, handle);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnUpdateSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    RegisterObserverForProcess(processInfo, paramSet);
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(sessionMgr == nullptr, HKS_ERROR_NULL_POINTER, "sessionMgr is null");
    ret = sessionMgr->ExtensionUpdateSession(processInfo, handle, paramSet, inData, outData);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnFinishSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    RegisterObserverForProcess(processInfo, paramSet);
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(sessionMgr == nullptr, HKS_ERROR_NULL_POINTER, "sessionMgr is null");
    ret = sessionMgr->ExtensionFinishSession(processInfo, handle, paramSet, inData, outData);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnAbortSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    RegisterObserverForProcess(processInfo, paramSet);
    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(sessionMgr == nullptr, HKS_ERROR_NULL_POINTER, "sessionMgr is null");
    ret = sessionMgr->ExtensionAbortSession(processInfo, handle, paramSet);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnClearUkeyPinAuthState(
    const HksProcessInfo &processInfo, const std::string &index)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    struct HksParam uid = {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = processInfo.uidInt};
    CppParamSet paramSet = CppParamSet({uid});
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    ret = handleMgr->RemoteClearPinStatus(processInfo, index, paramSet);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}

__attribute__((visibility("default"))) int32_t HksExtPluginOnGetRemoteProperty(
    const HksProcessInfo &processInfo, const std::string &index, const std::string &propertyId,
    const CppParamSet &paramSet, CppParamSet &outParams)
{
    int32_t ret = HKS_SUCCESS;
    HKS_LOG_I("enter %" LOG_PUBLIC "s", __PRETTY_FUNCTION__);
    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(handleMgr == nullptr, HKS_ERROR_NULL_POINTER, "handleMgr is null");
    ret = handleMgr->GetRemoteProperty(processInfo, index, propertyId, paramSet, outParams);
    HKS_LOG_I("leave %" LOG_PUBLIC "s, ret = %" LOG_PUBLIC "d", __FUNCTION__, ret);
    return ret;
}
}