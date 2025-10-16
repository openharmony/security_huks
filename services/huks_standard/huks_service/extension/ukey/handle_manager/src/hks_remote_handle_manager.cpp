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
    if (!root.SetValue("originalIndex", originalIndex)) {
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
    if (providerArray.IsNull() || !providerArray.IsArray()) {
        HKS_LOG_E("Parse provider certificate array failed");
        return HKS_ERROR_JSON_PARSE_FAILED;
    }
    
    int32_t certCount = providerArray.ArraySize();
    for (int32_t i = 0; i < certCount; i++) {
        CommJsonObject certObj = providerArray.GetElement(i);
        HKS_IF_TRUE_CONTINUE(certObj.IsNull())
        auto indexValue = certObj.GetValue("index");
        HKS_IF_TRUE_LOGE_RETURN(certObj.IsNull(), HKS_ERROR_JSON_PARSE_FAILED,
            "Parse provider certificate array failed")
        auto indexResult = indexValue.ToString();
        if (indexResult.first == HKS_SUCCESS && !indexResult.second.empty()) {
            std::string wrappedIndex;
            int32_t ret = WrapIndexWithProviderInfo(providerInfo, indexResult.second, wrappedIndex);
            if (ret == HKS_SUCCESS) {
                HKS_IF_TRUE_LOGE_RETURN(!certObj.SetValue("index", wrappedIndex), HKS_ERROR_JSON_SERIALIZE_FAILED,
                    "Set wrapped index failed")
            } else {
                HKS_LOG_E("Wrap index failed: %" LOG_PUBLIC "d", ret);
            }
        }
        HKS_IF_TRUE_LOGE_RETURN(!combinedArray.AppendElement(certObj), HKS_ERROR_JSON_SERIALIZE_FAILED,
            "Add certificate to combined array failed")
    }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseIndexAndProviderInfo(const std::string &index,
    ProviderInfo &providerInfo, std::string &newIndex)
{
    CommJsonObject root = CommJsonObject::Parse(index);
    HKS_IF_TRUE_LOGE_RETURN(root.IsNull(), HKS_ERROR_JSON_PARSE_FAILED,
        "Parse index failed, invalid JSON format")

    auto providerNameObj = root.GetValue(PROVIDER_NAME_KEY);
    auto abilityNameObj = root.GetValue(ABILITY_NAME_KEY);
    auto bundleNameObj = root.GetValue(BUNDLE_NAME_KEY);  
    HKS_IF_TRUE_LOGE_RETURN(providerNameObj.IsNull() || abilityNameObj.IsNull() || 
        bundleNameObj.IsNull(), HKS_ERROR_JSON_MISSING_KEY, "Required provider info fields are missing")
    auto providerNameResult = providerNameObj.ToString();
    auto abilityNameResult = abilityNameObj.ToString();
    auto bundleNameResult = bundleNameObj.ToString();
    HKS_IF_TRUE_LOGE_RETURN(providerNameResult.first != HKS_SUCCESS || abilityNameResult.first != HKS_SUCCESS ||
        bundleNameResult.first != HKS_SUCCESS, HKS_ERROR_JSON_TYPE_MISMATCH, "Get provider info fields failed")

    providerInfo.m_providerName = providerNameResult.second;
    providerInfo.m_abilityName = abilityNameResult.second;
    providerInfo.m_bundleName = bundleNameResult.second;
    HKS_IF_TRUE_LOGE_RETURN(providerInfo.m_providerName.empty() || providerInfo.m_abilityName.empty() ||
        providerInfo.m_bundleName.empty(), HKS_ERROR_JSON_INVALID_VALUE, "Provider info is incomplete")

    CommJsonObject newRoot = CommJsonObject::CreateObject();
    HKS_IF_TRUE_LOGE_RETURN(newRoot.IsNull(), HKS_ERROR_JSON_SERIALIZE_FAILED,
        "Create new JSON object failed")

    auto keys = root.GetKeys();
    for (const auto &key : keys) {
        if (key == PROVIDER_NAME_KEY || key == ABILITY_NAME_KEY || key == BUNDLE_NAME_KEY) {
            continue;
        }
        auto value = root.GetValue(key);
        if (!value.IsNull() && !newRoot.SetValue(key, value)) {
            HKS_LOG_E("Copy field %s failed", key.c_str());
            return HKS_ERROR_JSON_SERIALIZE_FAILED;
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
        ret = HKS_ERROR_REMOTE_PROXY_GET_FAILED;
        return nullptr;
    }
    
    ret = HKS_SUCCESS;
    return proxy;
}

int32_t HksRemoteHandleManager::CreateRemoteIndex(const ProviderInfo &providerInfo,
    const CppParamSet &paramSet, std::string &index)
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
    
    index = root.Serialize(false);
    return HKS_SUCCESS;
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
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)

    ret = ValidateAndGetHandle(newIndex, providerInfo, handle);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Validate provider info and get handle failed: %" LOG_PUBLIC "d", ret)
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const std::string &index, const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Parse index and provider info failed: %" LOG_PUBLIC "d", ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)
    
    std::string handle;
    auto ipccode = proxy->OpenRemoteHandle(newIndex, paramSet, handle, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Create remote handle failed: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(!indexToHandle_.Insert(newIndex, handle),
        HKS_ERROR_HANDLE_INSERT_ERROR, "Cache remote handle failed")
    
    if (!newIndexToProviderInfo_.Insert(newIndex, providerInfo)) {
        indexToHandle_.Erase(newIndex);
        HKS_LOG_E("Cache provider info failed");
        return HKS_ERROR_HANDLE_INSERT_ERROR;
    }
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const std::string &index, const CppParamSet &paramSet)
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
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote verify pin failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
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
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote verify pin status failed: %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
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
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    auto proxy = GetProviderProxy(providerInfo, ret);
    HKS_IF_NULL_RETURN(proxy, ret)

    auto ipccode = proxy->ExportCertificate(newIndex, paramSet, cert, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK, HKS_ERROR_IPC_MSG_FAIL, "remote ipc failed: %" LOG_PUBLIC "d", ipccode)
    
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_REMOTE_OPERATION_FAILED,
            "Remote ExportCertificate failed: %" LOG_PUBLIC "d", ret)
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
        HKS_IF_TRUE_LOGE_RETURN(ipccode != ERR_OK || ret != HKS_SUCCESS, ret,
            "ExportProviderCertificates for provider failed")
        
        ret = MergeProviderCertificates(providerInfo, tmpCertVec, combinedArray);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Merge certificates for provider failed")
    }
    
    certVec = combinedArray.Serialize(false);
    HKS_IF_TRUE_LOGE_RETURN(certVec.empty(), HKS_ERROR_JSON_SERIALIZE_FAILED, "Serialize certificate array failed")
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetRemoteProperty(const std::string &index, const std::string &propertyId,
    const CppParamSet &paramSet, CppParamSet &outParams)
{
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

int32_t HksRemoteHandleManager::ClearRemoteHandleMap()
{
    indexToHandle_.Clear();
    newIndexToProviderInfo_.Clear();
    return HKS_SUCCESS;
}

}
}
}