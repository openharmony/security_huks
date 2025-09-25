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
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_json_wrapper.h"
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

int32_t HksRemoteHandleManager::ParseIndexAndProviderInfo(const std::string &index, 
                                                        ProviderInfo &providerInfo, 
                                                        std::string &newIndex)
{
    CommJsonObject root = CommJsonObject::Parse(index);
    if (root.IsNull()) {
        HKS_LOG_E("Parse index failed, invalid JSON format");
        return HKS_ERROR_JSON_PARSE_FAILED;
    }

    auto providerNameObj = root.GetValue(PROVIDER_NAME_KEY);
    auto abilityNameObj = root.GetValue(ABILITY_NAME_KEY);
    auto bundleNameObj = root.GetValue(BUNDLE_NAME_KEY);
    
    if (providerNameObj.IsNull() || abilityNameObj.IsNull() || bundleNameObj.IsNull()) {
        HKS_LOG_E("Required provider info fields are missing");
        return HKS_ERROR_JSON_MISSING_KEY;
    }
    auto providerNameResult = providerNameObj.ToString();
    auto abilityNameResult = abilityNameObj.ToString();
    auto bundleNameResult = bundleNameObj.ToString();
    
    if (providerNameResult.first != HKS_SUCCESS || abilityNameResult.first != HKS_SUCCESS || 
        bundleNameResult.first != HKS_SUCCESS) {
        HKS_LOG_E("Get provider info fields failed");
        return HKS_ERROR_JSON_TYPE_MISMATCH;
    }
    
    providerInfo.m_providerName = providerNameResult.second;
    providerInfo.m_abilityName = abilityNameResult.second;
    providerInfo.m_bundleName = bundleNameResult.second;
    
    if (providerInfo.m_providerName.empty() || providerInfo.m_abilityName.empty() || 
        providerInfo.m_bundleName.empty()) {
        HKS_LOG_E("Provider info is incomplete");
        return HKS_ERROR_JSON_INVALID_VALUE;
    }
    CommJsonObject newRoot = CommJsonObject::CreateObject();
    if (newRoot.IsNull()) {
        HKS_LOG_E("Create new JSON object failed");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }

    auto keys = root.GetKeys();
    for (const auto &key : keys) {
        if (key != PROVIDER_NAME_KEY && key != ABILITY_NAME_KEY && key != BUNDLE_NAME_KEY) {
            auto value = root.GetValue(key);
            if (value.IsNull()) {
                continue;
            }
        
            if (!newRoot.SetValue(key, value)) {
                HKS_LOG_E("Copy field %s failed", key.c_str());
                return HKS_ERROR_JSON_SERIALIZE_FAILED;
            }
        }
    }
    
    std::string newJson = newRoot.Serialize(false);
    if (newIndex.empty()) {
        HKS_LOG_E("New index is empty");
        return HKS_ERROR_JSON_SERIALIZE_FAILED;
    }
    newIndex = newJson;

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ValidateProviderInfo(const std::string &newIndex, ProviderInfo &providerInfo)
{
    ProviderInfo cachedProviderInfo;
    if (!newIndexToProviderInfo.Find(newIndex, cachedProviderInfo)) {
        HKS_LOG_E("Provider info not found for newIndex: %s", newIndex.c_str());
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
        HKS_LOG_E("Get extension proxy failed for provider: %s", providerInfo.m_providerName.c_str());
        ret = HKS_ERROR_REMOTE_PROXY_GET_FAILED;
        return nullptr;
    }
    
    ret = HKS_SUCCESS;
    return proxy;
}

int32_t HksRemoteHandleManager::GetRemoteIndex(const ProviderInfo &providerInfo, [[maybe_unused]] const CppParamSet &paramSet, std::string &index)
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
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Provider info validation failed: %d", ret);
        return ret;
    }

    if (!indexToHandle.Find(newIndex, handle)) {
        HKS_LOG_E("Remote handle not found for newIndex: %s", newIndex.c_str());
        return HKS_ERROR_REMOTE_HANDLE_NOT_FOUND;
    }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseAndValidateIndex(const std::string &index, ProviderInfo &providerInfo,
                                    std::string &newIndex,std::string &handle)
{
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Parse index and provider info failed: %d", ret);
        return ret;
    }
    
    ret = ValidateAndGetHandle(newIndex, providerInfo, handle);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Validate provider info and get handle failed: %d", ret);
        return ret;
    }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const std::string &index, [[maybe_unused]] const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Parse index and provider info failed: %d", ret);
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }
    
    std::string handle = ""; 
    (void)proxy->OpenRemoteHandle(newIndex, paramSet, handle, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Create remote handle failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    if (!indexToHandle.Insert(newIndex, handle)) {
        HKS_LOG_E("Cache remote handle failed");
        return HKS_ERROR_HANDLE_INSERT_ERROR;
    }
    
    if (!newIndexToProviderInfo.Insert(newIndex, providerInfo)) {
        indexToHandle.Erase(newIndex); 
        HKS_LOG_E("Cache provider info failed");
        return HKS_ERROR_HANDLE_INSERT_ERROR;
    }

    HKS_LOG_I("Create remote handle success, newIndex: %s, handle: %s", 
            newIndex.c_str(), handle.c_str());
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const std::string &index, [[maybe_unused]] const CppParamSet &paramSet)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->CloseRemoteHandle(handle, paramSet, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Close remote handle failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    // 移除缓存
    indexToHandle.Erase(newIndex);
    newIndexToProviderInfo.Erase(newIndex);

    HKS_LOG_I("Close remote handle success, newIndex: %s", newIndex.c_str());
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t& authState, uint32_t& retryCnt)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }
    
    (void)proxy->AuthUkeyPin(handle, paramSet, ret, authState, retryCnt);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify pin failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &state)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->GetUkeyPinAuthState(handle, paramSet, state, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify pin status failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteClearPinStatus(const std::string &index)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    // 调用远程provider的清除PIN状态方法
    // ret = proxy->ClearPinStatus(newIndex, handle);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote clear pin status failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleSign(const std::string &index, const CppParamSet &paramSet,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->Sign(handle, paramSet, inData, outData, ret);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote sign failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleVerify(const std::string &index, const CppParamSet &paramSet,
    const std::vector<uint8_t> &plainText, std::vector<uint8_t> &signature)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string handle;
    int32_t ret = ParseAndValidateIndex(index, providerInfo, newIndex, handle);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->Verify(handle, paramSet, plainText, signature, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindRemoteCertificate(const std::string &index,
    const CppParamSet &paramSet, std::string cert)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->ExportCertificate(newIndex, paramSet, cert, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote ExportCertificate failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}
int32_t HksRemoteHandleManager::FindRemoteAllCertificate(const std::string &index,
    const CppParamSet &paramSet, std::string certVec)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    int32_t ret = ParseIndexAndProviderInfo(index, providerInfo, newIndex);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    (void)proxy->ExportProviderCertificates(paramSet, certVec, ret);
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote ExportProviderCertificates failed: %d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearRemoteHandle()
{
    indexToHandle.Clear();
    newIndexToProviderInfo.Clear();
    return HKS_SUCCESS;
}

}  // namespace Huks
}  // namespace Security
}  // namespace OHOS