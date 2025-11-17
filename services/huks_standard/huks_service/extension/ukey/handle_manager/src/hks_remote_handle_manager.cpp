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

#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_template.h"
#include "hks_ukey_common.h"
namespace OHOS {
namespace Security {
namespace Huks {

constexpr const char *PROVIDER_NAME_KEY = "providerName";
constexpr const char *ABILITY_NAME_KEY = "abilityName";
constexpr const char *BUNDLE_NAME_KEY = "bundleName";
constexpr const size_t MAX_INDEX_SIZE = 512;
constexpr const size_t MAX_PROVIDER_TOTAL_NUM = 100;
constexpr const size_t MAX_PROVIDER_NUM_PER_UID = 10;
const std::vector<std::string> VALID_PROPERTYID = {
    "SKF_EnumDev",
    "SKF_GetDevInfo",
    "SKF_EnumApplication",
    "SKF_EnumContainer",
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
    if (root.IsNull()) {
        HKS_LOG_E("Create JSON object failed");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }
    if (!root.SetValue(PROVIDER_NAME_KEY, providerInfo.m_providerName) ||
        !root.SetValue(ABILITY_NAME_KEY, providerInfo.m_abilityName) ||
        !root.SetValue(BUNDLE_NAME_KEY, providerInfo.m_bundleName)) {
        HKS_LOG_E("Set provider info to index failed");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }
    if (!root.SetValue("index", originalIndex)) {
        HKS_LOG_E("Set original index failed");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }
    wrappedIndex = root.Serialize(false);
    return HKS_SUCCESS;
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
        HKS_IF_TRUE_CONTINUE(indexResult.first != HKS_SUCCESS || indexResult.second.empty() ||
            indexResult.second.size() > MAX_INDEX_SIZE)
        std::string wrappedIndex;
        if (WrapIndexWithProviderInfo(providerInfo, indexResult.second, wrappedIndex) == HKS_SUCCESS) {
            HKS_IF_TRUE_CONTINUE(!certObj.SetValue("index", wrappedIndex))
        }
        HKS_IF_TRUE_CONTINUE(!combinedArray.AppendElement(certObj))
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseIndexAndProviderInfo(const std::string &index,
    ProviderInfo &providerInfo, std::string &newIndex)
{
    CommJsonObject root = CommJsonObject::Parse(index);
    HKS_IF_TRUE_LOGE_RETURN(root.IsNull(), HKS_ERROR_JSON_PARSE_FAILED,
        "Parse index failed, invalid JSON format")
    auto providerNameResult = root.GetValue(PROVIDER_NAME_KEY).ToString();
    auto abilityNameResult = root.GetValue(ABILITY_NAME_KEY).ToString();
    auto bundleNameResult = root.GetValue(BUNDLE_NAME_KEY).ToString();
    HKS_IF_TRUE_LOGE_RETURN(providerNameResult.first != HKS_SUCCESS || abilityNameResult.first != HKS_SUCCESS ||
        bundleNameResult.first != HKS_SUCCESS, HKS_ERROR_JSON_TYPE_MISMATCH, "Get provider info fields failed")

    providerInfo.m_providerName = providerNameResult.second;
    providerInfo.m_abilityName = abilityNameResult.second;
    providerInfo.m_bundleName = bundleNameResult.second;
    HKS_IF_TRUE_LOGE_RETURN(providerInfo.m_providerName.empty() || providerInfo.m_abilityName.empty() ||
        providerInfo.m_bundleName.empty(), HKS_ERROR_JSON_INVALID_VALUE, "Provider info is incomplete")

    CommJsonObject newRoot = CommJsonObject::CreateObject();
    HKS_IF_TRUE_LOGE_RETURN(newRoot.IsNull(), HKS_ERROR_JSON_NOT_OBJECT,
        "Create new JSON object failed")

    auto keys = root.GetKeys();
    for (const auto &key : keys) {
        if (key == PROVIDER_NAME_KEY || key == ABILITY_NAME_KEY || key == BUNDLE_NAME_KEY) {
            continue;
        }
        auto value = root.GetValue(key);
        if (!value.IsNull() && !newRoot.SetValue(key, value)) {
            HKS_LOG_E("Copy field %s failed", key.c_str());
            return HKS_ERROR_JSON_INVALID_VALUE;
        }
    }
    newIndex = newRoot.Serialize(false);
    HKS_IF_TRUE_LOGE_RETURN(newIndex.empty(), HKS_ERROR_JSON_SERIALIZE_FAILED,
        "New index is empty")
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ValidateProviderInfo(const std::string &newIndex, ProviderInfo &providerInfo)
{
    ProviderInfo cachedProviderInfo;
    if (!newIndexToProviderInfo_.Find(newIndex, cachedProviderInfo)) {
        HKS_LOG_E("Provider info not found for newIndex: %" LOG_PUBLIC "s", newIndex.c_str());
        return HKS_ERROR_REMOTE_HANDLE_NOT_FOUND;
    }
    
    if (!(cachedProviderInfo == providerInfo)) {
        HKS_LOG_E("Provider info mismatch");
        return HKS_ERROR_REMOTE_PROVIDER_MISMATCH;
    }
    
    return HKS_SUCCESS;
}

OHOS::sptr<IHuksAccessExtBase> HksRemoteHandleManager::GetProviderProxy(const ProviderInfo &providerInfo, int32_t &ret)
{
    auto providerManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerManager == nullptr) {
        HKS_LOG_E("Get provider manager instance failed");
        ret = HKS_ERROR_NULL_POINTER;
        return nullptr;
    }

    sptr<IHuksAccessExtBase> proxy;
    ret = providerManager->GetExtensionProxy(providerInfo, proxy);
    if (ret != HKS_SUCCESS || proxy == nullptr) {
        HKS_LOG_E("Get extension proxy failed for provider: %" LOG_PUBLIC "s", providerInfo.m_providerName.c_str());
        return nullptr;
    }
    
    ret = HKS_SUCCESS;
    return proxy;
}

int32_t HksRemoteHandleManager::ValidateAndGetHandle(const std::string &newIndex,
    ProviderInfo &providerInfo, std::string &handle)
{
    int32_t ret = ValidateProviderInfo(newIndex, providerInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Provider info validation failed: %" LOG_PUBLIC "d", ret)

    if (!indexToHandle_.Find(newIndex, handle)) {
        HKS_LOG_E("Remote handle not found for newIndex: %" LOG_PUBLIC "s", newIndex.c_str());
        return HKS_ERROR_REMOTE_HANDLE_NOT_FOUND;
    }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseAndValidateIndex(const std::string &index, ProviderInfo &providerInfo,
    std::string &newIndex, std::string &handle)
{
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    ret = ValidateAndGetHandle(newIndex, providerInfo, handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NOT_EXIST,
        "Validate provider info and get handle failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const std::string &index, const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)
    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)
    
    std::string handle;
    auto ipccode = proxy->OpenRemoteHandle(newIndex, paramSet, handle, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Create remote handle failed: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(!indexToHandle_.Insert(newIndex, handle),
        HKS_ERROR_CODE_KEY_ALREADY_EXIST, "Cache remote handle failed")
    if (!newIndexToProviderInfo_.Insert(newIndex, providerInfo)) {
        indexToHandle_.Erase(newIndex);
        HKS_LOG_E("Cache provider info failed");
        return HKS_ERROR_CODE_KEY_ALREADY_EXIST;
    }
    HKS_IF_TRUE_LOGE_RETURN(IsProviderNumExceedLimit(providerInfo),
        HUKS_ERR_CODE_EXCEED_LIMIT, "Provider num exceed limit")
    int32_t num = 0;
    if (providerInfoToNum_.Find(providerInfo, num)) {
        providerInfoToNum_.EnsureInsert(providerInfo, num + 1);
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->CloseRemoteHandle(handle, paramSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Close remote handle failed: %" LOG_PUBLIC "d", ret)
    indexToHandle_.Erase(newIndex);
    newIndexToProviderInfo_.Erase(newIndex);
    int32_t num = 0;
    if (providerInfoToNum_.Find(providerInfo, num)) {
        if (num == 1) {
            providerInfoToNum_.Erase(providerInfo);
        } else {
            providerInfoToNum_.EnsureInsert(providerInfo, num - 1);
        }
    }
    std::vector<std::pair<uint32_t, std::string>> keysToRemove;
    uidIndexToAuthState_.Iterate([&](std::pair<uint32_t, std::string> key, int32_t value) {
        if (key.first == processInfo.uidInt && key.second == index) {
            keysToRemove.push_back(key);
        }
    });
    for (auto &key : keysToRemove) {
        uidIndexToAuthState_.Erase(key);
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t& retryCnt)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)
    
    auto ipccode = proxy->AuthUkeyPin(handle, paramSet, ret, authState, retryCnt);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    if (authState == HKS_SUCCESS) {
        uidIndexToAuthState_.EnsureInsert(std::make_pair(processInfo.uidInt, index), HKS_SUCCESS);
    }
    if (ret == HUKS_ERR_CODE_PIN_CODE_ERROR || ret == HUKS_ERR_CODE_PIN_LOCKED) {
        HKS_IF_TRUE_LOGE(retryCnt > 0, "AuthUkeyPin failed: %" LOG_PUBLIC "d", ret)
    } else {
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote verify pin failed: %" LOG_PUBLIC "d", ret)
    }
    return ret;
}

int32_t HksRemoteHandleManager::RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->GetUkeyPinAuthState(handle, paramSet, state, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    HKS_IF_TRUE_LOGE_RETURN(ret != HUKS_ERR_CODE_PIN_LOCKED || ret != HKS_SUCCESS, HKS_ERROR_REMOTE_OPERATION_FAILED,
        "Remote verify pin status failed: %" LOG_PUBLIC "d", ret)
    return ret;
}

int32_t HksRemoteHandleManager::RemoteClearPinStatus(const std::string &index, const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ClearUkeyPinAuthState(newIndex, paramSet, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote clear pin status failed: %" "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleSign(const std::string &index, const CppParamSet &paramSet,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->Sign(handle, paramSet, inData, outData, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote sign failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleVerify(const std::string &index, const CppParamSet &paramSet,
    const std::vector<uint8_t> &plainText, std::vector<uint8_t> &signature)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->Verify(handle, paramSet, plainText, signature, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote verify failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteCertificate(const std::string &index,
    const CppParamSet &paramSet, std::string &cert)
{
    ProviderInfo providerInfo = {"", "", ""};
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT,
        "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ExportCertificate(newIndex, paramSet, cert, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote ExportCertificate failed: %" LOG_PUBLIC "d", ret)
    
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
    auto providerLifeManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerLifeManager == nullptr) {
        HKS_LOG_E("Get provider Life manager instance failed");
        return HKS_ERROR_NULL_POINTER;
    }
    std::vector<ProviderInfo> infos;
    int32_t ret = providerLifeManager->GetAllProviderInfosByProviderName(providerName, infos);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
            "GetAllProviderInfosByProviderName failed: %" LOG_PUBLIC "d", ret)
    
    CommJsonObject combinedArray = CommJsonObject::CreateArray();
    HKS_IF_TRUE_LOGE_RETURN(combinedArray.IsNull(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Create combined array failed")
    
    for (const auto &providerInfo : infos) {
        int32_t ret = HKS_SUCCESS;
        auto proxy = GetProviderProxy(providerInfo, ret);
        HKS_IF_TRUE_LOGE_CONTINUE(proxy == nullptr || ret != HKS_SUCCESS,
            "Get proxy for provider failed, skipping")
        std::string tmpCertVec = "";
        auto ipccode = proxy->ExportProviderCertificates(paramSet, tmpCertVec, ret);
        HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL,
            "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
        HKS_IF_TRUE_LOGE_CONTINUE(ret != HKS_SUCCESS, "ExportProviderCertificates for provider failed")

        ret = MergeProviderCertificates(providerInfo, tmpCertVec, combinedArray);
        HKS_IF_TRUE_LOGE_CONTINUE(ret != HKS_SUCCESS, "Merge certificates for provider failed")
    }
    
    certVec = combinedArray.Serialize(false);
    HKS_IF_TRUE_LOGE_RETURN(certVec.empty(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Serialize certificate array failed")
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetRemoteProperty(const std::string &index, const std::string &propertyId,
    const CppParamSet &paramSet, CppParamSet &outParams)
{
    if (std::find(VALID_PROPERTYID.begin(), VALID_PROPERTYID.end(), propertyId) == VALID_PROPERTYID.end()) {
        HKS_LOG_E("Invalid propertyId");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->GetProperty(handle, propertyId, paramSet, outParams, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote GetProperty failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearRemoteHandleMap(const std::string &providerName, const std::string &abilityName)
{
    std::vector<std::string> indicesToRemove;
    std::vector<ProviderInfo> providersToRemove;
    auto collectToRemoveFunc = [&](std::string key, ProviderInfo &value) {
        if (value.m_providerName == providerName) {
            if (abilityName.empty() || value.m_abilityName == abilityName) {
                indicesToRemove.push_back(key);
                providersToRemove.push_back(value);
            }
        }
    };
    newIndexToProviderInfo_.Iterate(collectToRemoveFunc);
    for (std::string index : indicesToRemove) {
        indexToHandle_.Erase(index);
        newIndexToProviderInfo_.Erase(index);
    }
    for (ProviderInfo providerInfo : providersToRemove) {
        providerInfoToNum_.Erase(providerInfo);
    }
    return HKS_SUCCESS;
}

bool HksRemoteHandleManager::CheckAuthStateIsOk(const HksProcessInfo &processInfo, const std::string &index)
{
    int32_t state = 0;
    return uidIndexToAuthState_.Find(std::make_pair(processInfo.uidInt, index), state);
}

bool HksRemoteHandleManager::IsProviderNumExceedLimit(const ProviderInfo &providerInfo)
{
    int32_t num = 0;
    if (providerInfoToNum_.Find(providerInfo, num)) {
        return num >= MAX_PROVIDER_NUM_PER_UID - 1;
    }
    int32_t totalNum = 0;
    auto iterFunc = [&](ProviderInfo key, int32_t value) {
        totalNum += value;
    };
    providerInfoToNum_.Iterate(iterFunc);
    return totalNum >= MAX_PROVIDER_TOTAL_NUM - 1;
}

}
}
}