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
 
#include "hks_remote_handle_manager.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <shared_mutex>
#include <string>
#include <vector>

#include "hks_ukey_common.h"
#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_template.h"
#include "hks_ukey_common.h"
#include "hks_ukey_system_adapter.h"
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "hks_json_wrapper.h"
namespace OHOS {
namespace Security {
namespace Huks {

constexpr const size_t MAX_INDEX_SIZE = 512;
constexpr const int32_t MAX_PROVIDER_TOTAL_NUM = 100;
const std::vector<std::string> VALID_PROPERTYID = {
    "SKF_EnumDev",
    "SKF_GetDevInfo",
    "SKF_EnumApplication",
    "SKF_EnumContainer",
    "SKF_ExportPublicKey",
};

std::shared_ptr<HksRemoteHandleManager> HksRemoteHandleManager::GetInstanceWrapper()
{
    return HksRemoteHandleManager::GetInstance();
}

void HksRemoteHandleManager::ReleaseInstance()
{
    HksRemoteHandleManager::DestroyInstance();
}

static int32_t WrapIndexWithProviderInfo(const ProviderInfo& providerInfo, const std::string& originalIndex,
    std::string& wrappedIndex)
{
    CommJsonObject root = CommJsonObject::CreateObject();
    HKS_IF_TRUE_LOGE_RETURN(root.IsNull(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Create JSON object failed")
    if (!root.SetValue(PROVIDER_NAME_KEY, providerInfo.m_providerName) ||
        !root.SetValue(ABILITY_NAME_KEY, providerInfo.m_abilityName) ||
        !root.SetValue(BUNDLE_NAME_KEY, providerInfo.m_bundleName)) {
        HKS_LOG_E("Set provider info to index failed");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }
    HKS_IF_TRUE_LOGE_RETURN(!root.SetValue("index", originalIndex), HKS_ERROR_JSON_SERIALIZE_FAILED,
        "Set original index failed")
    wrappedIndex = root.Serialize(false);
    return HKS_SUCCESS;
}

static void ConvertCertInfoToIdl(const struct HksExtCertInfo &certInfo, HksExtCertInfoIdl &idlOut)
{
    idlOut.purpose = certInfo.purpose;
    
    // 转换 index
    if (certInfo.index.data != nullptr && certInfo.index.size > 0) {
        idlOut.index.assign(certInfo.index.data, certInfo.index.data + certInfo.index.size);
    } else {
        idlOut.index.clear();
    }
    
    // 转换 cert
    if (certInfo.cert.data != nullptr && certInfo.cert.size > 0) {
        idlOut.cert.assign(certInfo.cert.data, certInfo.cert.data + certInfo.cert.size);
    } else {
        idlOut.cert.clear();
    }
}

int32_t HksRemoteHandleManager::MergeProviderCertificates(const ProviderInfo &providerInfo,
    const std::string &providerCertVec, CommJsonObject &combinedArray)
{
    CommJsonObject providerArray = CommJsonObject::Parse(providerCertVec);
    int32_t certCount = providerArray.ArraySize();
    HKS_IF_TRUE_LOGE_RETURN(certCount < 0, HKS_ERROR_JSON_SERIALIZE_FAILED, "invalid providerCertVec")
    for (int32_t i = 0; i < certCount; i++) {
        CommJsonObject certObj = providerArray.GetElement(i);
        auto indexValue = certObj.GetValue("index");
        certObj.RemoveKey("index");
        auto indexResult = indexValue.ToString();
        HKS_IF_TRUE_LOGE_CONTINUE(indexResult.first != HKS_SUCCESS || indexResult.second.empty() ||
            indexResult.second.size() > MAX_INDEX_SIZE,
            "Failed to convert indexValue to string, error code: %" LOG_PUBLIC "d", indexResult.first)
        std::string wrappedIndex;
        if (WrapIndexWithProviderInfo(providerInfo, indexResult.second, wrappedIndex) == HKS_SUCCESS) {
            HKS_IF_TRUE_CONTINUE(!certObj.SetValue("index", wrappedIndex))
        }
        HKS_IF_TRUE_LOGE(!combinedArray.AppendElement(certObj), "append certObj to combinedArray fail.")
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetProviderProxy(const ProviderInfo &providerInfo,
    OHOS::sptr<IHuksAccessExtBase> &proxy)
{
    auto providerManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerManager == nullptr, HKS_ERROR_NULL_POINTER, "Get provider manager instance failed")
    int32_t ret = providerManager->GetExtensionProxy(providerInfo, proxy);
    if (ret != HKS_SUCCESS || proxy == nullptr) {
        HKS_LOG_E("Get extension proxy failed for provider: %" LOG_PUBLIC "s", providerInfo.m_providerName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseAndValidateIndex(const std::string &index, const uint32_t uid,
    ProviderInfo &providerInfo, std::string &handle)
{
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    HKS_IF_TRUE_LOGE_RETURN(!uidIndexToHandle_.Find({uid, index}, handle), HKS_ERROR_NOT_EXIST,
        "Remote handle not found for uid: %" LOG_PUBLIC "u, index: %" LOG_PUBLIC "s", uid, index.c_str())
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo{};
    std::string newIndex;
    ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)
    
    std::string handle;
    auto ipccode = proxy->OpenRemoteHandle(newIndex, newParamSet, handle, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_openResourceErrCodeMapping);
    ClearMapByHandle(ret, handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Create remote handle failed: %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("uidIndexToHandle_ is %" LOG_PUBLIC "u,%" LOG_PUBLIC "s", processInfo.uidInt, index.c_str());
    HKS_IF_TRUE_LOGE_RETURN(IsProviderNumExceedLimit(providerInfo),
        HKS_ERROR_HANDLE_REACH_MAX_NUM, "Provider num exceed limit")
    int32_t num = 0;
    (void)providerInfoToNum_.Find(providerInfo, num);
    providerInfoToNum_.EnsureInsert(providerInfo, num + 1);
    if (!uidIndexToHandle_.Insert({processInfo.uidInt, index}, handle)) {
        providerInfoToNum_.EnsureInsert(providerInfo, num);
        return HKS_ERROR_CODE_KEY_ALREADY_EXIST;
    }
    uidIndexToAuthState_.EnsureInsert(std::make_pair(processInfo.uidInt, index), 0);
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo{};
    std::string handle;
    ret = ParseAndValidateIndex(index, processInfo.uidInt, providerInfo, handle);
    HKS_IF_TRUE_RETURN(ret == HKS_ERROR_NOT_EXIST, HKS_SUCCESS)
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, HKS_SUCCESS)

    auto ipccode = proxy->CloseRemoteHandle(handle, newParamSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_closeResourceErrCodeMapping);
    ClearMapByHandle(ret, handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Close remote handle failed: %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("uidIndexToHandle_ is %" LOG_PUBLIC "u,%" LOG_PUBLIC "s", processInfo.uidInt, index.c_str());
    HKS_IF_NOT_SUCC_LOGE(RemoteClearPinStatus(processInfo, index, newParamSet),
        "Remote clear pin status failed: %" LOG_PUBLIC "u", processInfo.uidInt)
    uidIndexToAuthState_.Erase({processInfo.uidInt, index});
    uidIndexToHandle_.Erase({processInfo.uidInt, index});
    int32_t num = 0;
    if (providerInfoToNum_.Find(providerInfo, num)) {
        if (num == 1) {
            providerInfoToNum_.Erase(providerInfo);
        } else {
            providerInfoToNum_.EnsureInsert(providerInfo, num - 1);
        }
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t& retryCnt)
{
    auto accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
    HKS_IF_NOT_TRUE_LOGE_RETURN(OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx),
        HKS_ERROR_NOT_SYSTEM_APP, "RemoteVerifyPin: not system hap, check permission failed.");

    auto uid = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    HKS_IF_TRUE_LOGE_RETURN(uid.first != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "Get uid tag failed. ret: %" LOG_PUBLIC "d", uid.first)
    auto pin = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UKEY_PIN>();
    HKS_IF_TRUE_LOGE_RETURN(pin.first != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "Get pin failed. ret: %" LOG_PUBLIC "d", pin.first)
    ProviderInfo providerInfo{};
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, uid.second, providerInfo, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    int32_t userId = HksGetUserIdFromUid(uid.second);
    providerInfo.m_userid = userId;
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)
    
    auto ipccode = proxy->AuthUkeyPin(handle, paramSet, ret, authState, retryCnt);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_authPinErrCodeMapping);
    ClearMapByHandle(ret, handle);
    if (ret == HUKS_ERR_CODE_PIN_CODE_ERROR || ret == HUKS_ERR_CODE_PIN_LOCKED) {
        uidIndexToAuthState_.EnsureInsert(std::make_pair(static_cast<uint32_t>(uid.second), index), 0);
        HKS_LOG_E("AuthUkeyPin failed: %" LOG_PUBLIC "d", ret);
        return ret;
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote verify pin failed: %" LOG_PUBLIC "d", ret)
    uidIndexToAuthState_.EnsureInsert(std::make_pair(static_cast<uint32_t>(uid.second), index), 1);
    return ret;
}

int32_t HksRemoteHandleManager::RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    uint32_t uid = processInfo.uidInt;
    auto uidParam = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    HKS_IF_TRUE_EXCU(uidParam.first == HKS_SUCCESS, uid = static_cast<uint32_t>(uidParam.second));

    ProviderInfo providerInfo{};
    std::string handle;
    ret = ParseAndValidateIndex(index, uid, providerInfo, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    int32_t userId = HksGetUserIdFromUid(uid);
    providerInfo.m_userid = userId;
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->GetUkeyPinAuthState(handle, newParamSet, state, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_getPinAuthStateErrCodeMapping);
    ClearMapByHandle(ret, handle);
    uidIndexToAuthState_.EnsureInsert({uid, index}, state);
    if (ret == HUKS_ERR_CODE_PIN_LOCKED || ret == HKS_SUCCESS) {
        return ret;
    }
    HKS_LOG_E("Remote verify pin status failed: %" LOG_PUBLIC "d", ret);
    return ret;
}

int32_t HksRemoteHandleManager::RemoteClearPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo{};
    std::string handle;
    ret = ParseAndValidateIndex(index, processInfo.uidInt, providerInfo, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ClearUkeyPinAuthState(handle, newParamSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_clearPinStateErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote clear pin status failed")
    uidIndexToAuthState_.EnsureInsert(std::make_pair(processInfo.uidInt, index), 0);
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteCertificate(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &cert)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo = {"", "", ""};
    std::string newIndex;
    ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    int32_t frontUserId;
    ret = HksGetFrontUserId(frontUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get front user id failed")
    providerInfo.m_userid = frontUserId;
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ExportCertificate(newIndex, newParamSet, cert, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_exportCertErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote ExportCertificate failed: %" LOG_PUBLIC "d", ret)
    
    CommJsonObject combinedArray = CommJsonObject::CreateArray();
    HKS_IF_TRUE_LOGE_RETURN(combinedArray.IsNull(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Create combined array failed")
    ret = MergeProviderCertificates(providerInfo, cert, combinedArray);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Merge provider certificates failed: %" LOG_PUBLIC "d", ret)
    cert = combinedArray.Serialize(false);
    HKS_IF_TRUE_LOGE_RETURN(cert.empty(), HKS_ERROR_INVALID_ARGUMENT, "Serialize failed")
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteAllCertificate(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certVec)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    auto providerLifeManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(providerLifeManager == nullptr, HKS_ERROR_NULL_POINTER,
        "Get provider Life manager instance failed")
    std::vector<ProviderInfo> infos;
    ret = providerLifeManager->GetAllProviderInfosByProviderName(providerName, processInfo.userIdInt, infos);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetAllProviderInfosByProviderName failed: %" LOG_PUBLIC "d", ret)
    
    CommJsonObject combinedArray = CommJsonObject::CreateArray();
    HKS_IF_TRUE_LOGE_RETURN(combinedArray.IsNull(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Create combined array failed")
    uint32_t failNum = 0;
    for (const auto &providerInfo : infos) {
        HKS_IF_TRUE_EXCU(ret != HKS_SUCCESS, ++failNum);
        OHOS::sptr<IHuksAccessExtBase> proxy;
        ret = GetProviderProxy(providerInfo, proxy);
        HKS_IF_TRUE_LOGE_CONTINUE(ret != HKS_SUCCESS || proxy == nullptr,
            "Get proxy for provider failed, skipping")
        std::string tmpCertVec = "";
        auto ipccode = proxy->ExportProviderCertificates(newParamSet, tmpCertVec, ret);
        HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL,
            "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
        HKS_IF_TRUE_LOGE_CONTINUE(ret != HKS_SUCCESS, "ExportProviderCertificates for provider failed")

        ret = MergeProviderCertificates(providerInfo, tmpCertVec, combinedArray);
        HKS_IF_TRUE_LOGE_CONTINUE(ret != HKS_SUCCESS, "Merge certificates for provider failed")
    }
    HKS_IF_TRUE_EXCU(ret != HKS_SUCCESS, ++failNum);
    HKS_IF_TRUE_LOGE_RETURN(failNum == static_cast<uint32_t>(infos.size()), HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR,
        "get cert from all provider failed")
    certVec = combinedArray.Serialize(false);
    HKS_IF_TRUE_LOGE_RETURN(certVec.empty(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Serialize certificate array failed")
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ImportRemoteCertificate(const HksProcessInfo &processInfo, const std::string &index,
    const struct HksExtCertInfo &certInfo, const CppParamSet &paramSet)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo = {"", "", ""};
    std::string newIndex;
    ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    int32_t frontUserId;
    ret = HksGetFrontUserId(frontUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get front user id failed")
    providerInfo.m_userid = frontUserId;
    
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    HksExtCertInfoIdl certInfoIdl;
    ConvertCertInfoToIdl(certInfo, certInfoIdl);

    auto ipccode = proxy->ImportCertificate(newIndex, certInfoIdl, newParamSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    ret = ConvertExtensionToHksErrorCode(ret, g_importCertErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote ImportCertificate failed: %" LOG_PUBLIC "d", ret)

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetRemoteProperty(const HksProcessInfo &processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    uint32_t uid = processInfo.uidInt;
    auto uidParam = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    HKS_IF_TRUE_EXCU(uidParam.first == HKS_SUCCESS, uid = static_cast<uint32_t>(uidParam.second));
    if (!OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        HKS_IF_TRUE_LOGE_RETURN(propertyId == "SKF_ExportPublicKey", HKS_ERROR_INVALID_ARGUMENT,
            "Non-system app are not allowed to use SKF_ExportPublicKey")
    }
    if (std::find(VALID_PROPERTYID.begin(), VALID_PROPERTYID.end(), propertyId) == VALID_PROPERTYID.end()) {
        HKS_LOG_E("Invalid propertyId");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ProviderInfo providerInfo{};
    std::string handle;
    ret = ParseAndValidateIndex(index, uid, providerInfo, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    int32_t userId = HksGetUserIdFromUid(uid);
    providerInfo.m_userid = userId;
    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->GetProperty(handle, propertyId, paramSet, outParams, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_getPropertyErrCodeMapping);
    ClearMapByHandle(ret, handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote GetProperty failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteImportWrappedKey(const HksProcessInfo &processInfo, const std::string &index,
    const std::string &wrappingKeyIndex, const CppParamSet &paramSet, const std::vector<uint8_t> &wrappedData)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    std::string newIndex;
    ProviderInfo providerInfo{};
    ret = ParseAndValidateIndex(index, processInfo.uidInt, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ParseIndexAndProviderInfo failed, ret = %" LOG_PUBLIC "d", ret)
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);

    std::string newWrappingKeyIndex;
    ProviderInfo wrappingKeyProviderInfo;
    ret = ParseAndValidateIndex(wrappingKeyIndex, processInfo.uidInt, providerInfo, newWrappingKeyIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "ParseAndValidateIndex for wrapping key failed, ret = %" LOG_PUBLIC "d", ret)

    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ImportWrappedKey(newIndex, newWrappingKeyIndex, newParamSet, wrappedData, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_importWrappedKeyErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Remote ImportWrappedKey failed: %" LOG_PUBLIC "d", ret)

    return ret;
}

int32_t HksRemoteHandleManager::RemoteExportPublicKey(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::vector<uint8_t> &outData)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    std::string newIndex;
    ProviderInfo providerInfo;
    ret = ParseAndValidateIndex(index, processInfo.uidInt, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ParseIndexAndProviderInfo failed, ret = %" LOG_PUBLIC "d", ret)
    providerInfo.m_userid = HksGetUserIdFromUid(processInfo.uidInt);

    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ExportPublicKey(newIndex, newParamSet, outData, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK,
        HKS_ERROR_IPC_MSG_FAIL, "ExportPublicKey failed, ret = %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_exportPublicKeyErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ExportPublicKey failed, ret = %" LOG_PUBLIC "d", ret)

    return ret;
}

int32_t HksRemoteHandleManager::ExtensionGenerateKey(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo{};
    std::string handle;
    ret = ParseAndValidateIndex(index, processInfo.uidInt, providerInfo, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    int32_t userId = HksGetUserIdFromUid(processInfo.uidInt);
    providerInfo.m_userid = userId;

    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->GenerateKey(handle, paramSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL,
        "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    ret = ConvertExtensionToHksErrorCode(ret, g_generateKeyErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ExtensionGenerateKey failed, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("leave HksRemoteHandleManager::GenerateKey, ret = %" LOG_PUBLIC "d", ret);
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetResourceId(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &resourceId)
{
    CppParamSet newParamSet{};
    int32_t ret = VerifyCallerAndAdjustUidParam(processInfo, paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "uid check in %" LOG_PUBLIC "s failed.", __PRETTY_FUNCTION__)

    ProviderInfo providerInfo{};

    HKS_IF_TRUE_RETURN(!CheckStringParamLenIsOk(providerName, 1, MAX_PROVIDER_NAME_LEN), HKS_ERROR_INVALID_ARGUMENT)

    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    HKS_IF_NOT_SUCC_LOGE_RETURN(abilityName.first, HKS_ERROR_ABILITY_NAME_MISSING, "AbilityName not passed.")
    HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() >= MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())

    auto bundleName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_BUNDLE_NAME>();
    HKS_IF_NOT_SUCC_LOGE_RETURN(bundleName.first, HKS_ERROR_BUNDLE_NAME_MISSING, "BundleName not passed.")
    HKS_IF_TRUE_LOGE_RETURN(
        bundleName.second.size() > MAX_BUNDLE_NAME_LEN || bundleName.second.size() < MIN_BUNDLE_NAME_LEN,
        HKS_ERROR_INVALID_ARGUMENT, "the bundleName is too long. size: %" LOG_PUBLIC "zu", bundleName.second.size())

    auto resourceInfo = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_RESOURCE_INFO>();
    HKS_IF_NOT_SUCC_LOGE_RETURN(resourceInfo.first, HKS_ERROR_RESOURCE_INFO_MISSING, "ResourceInfo not passed.")
    HKS_IF_TRUE_LOGE_RETURN(resourceInfo.second.size() < 1, HKS_ERROR_INVALID_ARGUMENT,
        "the resourceInfo is too short. size: %" LOG_PUBLIC "zu", resourceInfo.second.size())

    int32_t userId = HksGetUserIdFromUid(processInfo.uidInt);
    providerInfo.m_userid = userId;
    providerInfo.m_abilityName = std::string(abilityName.second.begin(), abilityName.second.end());
    providerInfo.m_bundleName = std::string(bundleName.second.begin(), bundleName.second.end());
    providerInfo.m_providerName = providerName;

    OHOS::sptr<IHuksAccessExtBase> proxy;
    ret = GetProviderProxy(providerInfo, proxy);
    HKS_IF_NULL_RETURN(proxy, ret)

    std::string resourceResult;
    auto ipccode = proxy->GetResourceId(newParamSet, resourceResult, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    ret = ConvertExtensionToHksErrorCode(ret, g_getResourceIdErrCodeMapping);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetResourceId failed, ret = %" LOG_PUBLIC "d", ret)
    
    resourceId = resourceResult;
    HKS_LOG_I("leave HksRemoteHandleManager::GetResourceId, ret = %" LOG_PUBLIC "d", ret);
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearUidIndexMap(const ProviderInfo &providerInfo)
{
    std::vector<std::pair<uint32_t, std::string>> indicesToRemove;
    std::vector<ProviderInfo> providersToRemove;
    auto collectToRemoveFunc = [&](std::pair<uint32_t, std::string> key, std::string &value) {
        std::string newIndex;
        ProviderInfo tmpInfo{};
        int32_t ret = ParseIndexAndProviderInfo(key.second, tmpInfo, newIndex);
        HKS_IF_TRUE_LOGE(ret != HKS_SUCCESS, "ParseIndexAndProviderInfo failed: %" LOG_PUBLIC "d", ret)
        if (providerInfo.m_userid == HksGetUserIdFromUid(key.first) &&
            tmpInfo.m_providerName == providerInfo.m_providerName &&
            tmpInfo.m_bundleName == providerInfo.m_bundleName) {
            if (providerInfo.m_abilityName.empty() || tmpInfo.m_abilityName == providerInfo.m_abilityName) {
                indicesToRemove.push_back(key);
                tmpInfo.m_userid = providerInfo.m_userid;
                providersToRemove.push_back(tmpInfo);
            }
        }
    };
    uidIndexToHandle_.Iterate(collectToRemoveFunc);
    for (auto &key : indicesToRemove) {
        uidIndexToHandle_.Erase(key);
        uidIndexToAuthState_.Erase(key);
    };
    for (ProviderInfo tmpInfo : providersToRemove) {
        providerInfoToNum_.Erase(tmpInfo);
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CheckAuthStateIsOk(const HksProcessInfo &processInfo, const std::string &index)
{
    int32_t state = 0;
    HKS_IF_NOT_TRUE_RETURN(uidIndexToAuthState_.Find(std::make_pair(processInfo.uidInt, index), state),
        HKS_ERROR_NOT_EXIST)
    HKS_IF_NOT_TRUE_RETURN(state == 1, HKS_ERROR_PIN_NO_AUTH)
    return HKS_SUCCESS;
}

void HksRemoteHandleManager::ClearAuthState(const HksProcessInfo &processInfo)
{
    std::vector<std::pair<uint32_t, std::string>> keysToRemove;
    auto iterFunc = [&](std::pair<uint32_t, std::string> key, int32_t &value) {
        if (key.first == processInfo.uidInt) {
            keysToRemove.push_back(key);
        }
    };
    uidIndexToAuthState_.Iterate(iterFunc);
    struct HksParam uid = {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = processInfo.uidInt};
    CppParamSet paramSet = CppParamSet({uid});
    
    for (auto &key : keysToRemove) {
        HKS_IF_NOT_SUCC_LOGE(RemoteClearPinStatus(processInfo, key.second, paramSet),
            "Remote clear pin status failed: %" LOG_PUBLIC "u", processInfo.uidInt)
    }
}

bool HksRemoteHandleManager::IsProviderNumExceedLimit(const ProviderInfo &providerInfo)
{
    int32_t num = 0;
    if (providerInfoToNum_.Find(providerInfo, num)) {
        return num >= MAX_PROVIDER_TOTAL_NUM;
    }
    return false;
}

void HksRemoteHandleManager::ClearMapByHandle(const int32_t &ret, const std::string &handle)
{
    if (ret != HUKS_ERR_CODE_CRYPTO_FAIL && ret != HUKS_ERR_CODE_ITEM_NOT_EXIST) {
        return;
    }
    std::vector<std::pair<uint32_t, std::string>> keysToRemove;
    auto iterFunc = [&](std::pair<uint32_t, std::string> key, std::string &value) {
        if (value == handle) {
            keysToRemove.push_back(key);
        }
    };
    uidIndexToHandle_.Iterate(iterFunc);
    for (auto &key : keysToRemove) {
        std::string newIndex;
        ProviderInfo tmpInfo{};
        (void)ParseIndexAndProviderInfo(key.second, tmpInfo, newIndex);
        tmpInfo.m_userid = HksGetUserIdFromUid(key.first);
        providerInfoToNum_.Erase(tmpInfo);
        uidIndexToHandle_.Erase(key);
        uidIndexToAuthState_.Erase(key);
    }
}

void HksRemoteHandleManager::ClearMapByUid(const uint32_t uid)
{
    std::vector<std::pair<uint32_t, std::string>> keysToRemove;
    struct HksParam uidParam = {.tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(uid)};
    CppParamSet paramSet = CppParamSet({uidParam});
    HksProcessInfo processInfo = {};
    processInfo.uidInt = uid;
    auto iterFunc = [&](std::pair<uint32_t, std::string> key, std::string &value) {
        if (key.first == uid) {
            keysToRemove.push_back(key);
        }
    };
    uidIndexToHandle_.Iterate(iterFunc);
    for (auto &key : keysToRemove) {
        HKS_IF_NOT_SUCC_LOGE(CloseRemoteHandle(processInfo,  key.second, paramSet),
            "Remote close handle failed: %" LOG_PUBLIC "u", uid)
    }
}

int32_t HksRemoteHandleManager::VerifyCallerAndAdjustUidParam(const HksProcessInfo &processInfo,
    const CppParamSet &paramSet, CppParamSet &newParamSet)
{
    newParamSet = paramSet;
    auto uidParam = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_UID>();
    if (uidParam.first != HKS_SUCCESS) {
        std::vector<HksParam> params = {
            { .tag = HKS_EXT_CRYPTO_TAG_UID, .int32Param = static_cast<int32_t>(processInfo.uidInt)}
        };
        HKS_IF_NOT_TRUE_LOGE_RETURN(newParamSet.AddParams(params),
            HKS_ERROR_INVALID_ARGUMENT, "add uid to paramset fail.")
        return HKS_SUCCESS;
    }
    
    auto accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
    HKS_IF_NOT_TRUE_LOGE_RETURN(OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx),
        HKS_ERROR_NOT_SYSTEM_APP, "VerifyCallerAndAdjustUidParam: not system hap, check permission failed.");

    return HKS_SUCCESS;
}

}
}
}
