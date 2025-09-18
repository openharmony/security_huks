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

constexpr const char *PROVIDER_INFO_KEY = "providerInfo";
std::shared_ptr<HksRemoteHandleManager> HksRemoteHandleManager::GetInstanceWrapper()
{
    if (blob == nullptr) {
        return;
    }

    if (blob->data != nullptr) {
        HKS_FREE(blob->data);
        blob->data = nullptr;
    }
    blob->size = 0;

    HKS_FREE(blob);
    blob = nullptr;
}

void HksRemoteHandleManager::ReleaseInstance()
{
    OHOS::DelayedSingleton<HksRemoteHandleManager>::DestroyInstance();
}

int32_t HksRemoteHandleManager::ParseIndexAndProviderInfo(const std::string &index, 
                                                         std::string &providerInfo, 
                                                         std::string &newIndex)
{
    CommJsonObject root = CommJsonObject::Parse(index);

    auto providerInfoResult = root.GetValue(PROVIDER_INFO_KEY).ToString();
    if (providerInfoResult.first != HKS_SUCCESS) {
        HKS_LOG_E("Get providerInfo field failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    providerInfo = providerInfoResult.second;
    
    if (providerInfo.empty()) {
        HKS_LOG_E("ProviderInfo is empty");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // Create a new JSON object without the provider info field
    CommJsonObject newRoot = CommJsonObject::CreateObject();

    // Copy all fields except provider info
    auto keys = root.GetKeys();
    for (const auto &key : keys) {
        if (key != PROVIDER_INFO_KEY) {
            auto value = root.GetValue(key);
            if (!newRoot.SetValue(key, std::move(value))) {
                HKS_LOG_E("Copy all fields except provider info failed");
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    
    std::string newJson = newRoot.Serialize(false);
    newIndex = newJson;
    
    if (newIndex.empty()) {
        HKS_LOG_E("New index is empty");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    (void)memcpy_s(data, src.size, src.data, src.size);
    dest.data = data;
    dest.size = src.size;
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ValidateProviderInfo(const std::string &newIndex, const std::string &providerInfo)
{
    
    if (cachedProviderInfo != providerInfo) {
        HKS_LOG_E("Provider info mismatch: cached=%s, current=%s", 
                 cachedProviderInfo.c_str(), providerInfo.c_str());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    return HKS_SUCCESS;
}
OHOS::sptr<IRemoteObject> HksRemoteHandleManager::GetProviderProxy(const std::string &providerInfo, int32_t &ret)
{
    auto providerManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerManager == nullptr) {
        HKS_LOG_E("Get provider manager instance failed");
        ret = HKS_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }

    auto proxy = providerManager->GetExtensionProxy(providerInfo);
    if (proxy == nullptr) {
        HKS_LOG_E("Get extension proxy failed for provider: %s", providerInfo.c_str());
        ret = HKS_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    
    ret = HKS_SUCCESS;
    return proxy;
}

int32_t HksRemoteHandleManager::GetRemoteIndex(const std::string &providerInfo, [[maybe_unused]] const CppParamSet &paramSet, std::string &index)
{
    int32_t ret;
    auto proxy = GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }

    return HKS_SUCCESS;
}


int32_t HksRemoteHandleManager::ValidateAndGetHandle(const std::string &newIndex, 
                                                    const std::string &providerInfo, std::string &handle)
{
    int32_t ret = ValidateProviderInfo(newIndex, providerInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Provider info validation failed: %d", ret);
        return ret;
    }

    if (!indexToHandle.Find(newIndex, handle)) {
        HKS_LOG_E("Remote handle not found for newIndex: %s", newIndex.c_str());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ParseAndValidateIndex(const std::string &index, std::string &providerInfo,
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
    std::string providerInfo;
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

    // int32_t ret = proxy->CreateRemoteHandle(newIndex, paramSet, handle);
    std::string handle = "remote_handle_" + newIndex; 
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Create remote handle failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (!indexToHandle.Insert(newIndex, handle)) {
        HKS_LOG_E("Cache remote handle failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    if (!newIndexToProviderInfo.Insert(newIndex, providerInfo)) {
        indexToHandle.Erase(newIndex); 
        HKS_LOG_E("Cache provider info failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CloseRemoteHandle(const std::string &index, [[maybe_unused]] const CppParamSet &paramSet)
{
    std::string providerInfo;
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

    // ret = proxy->CloseRemoteHandle(newIndex, handle);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Close remote handle failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // 移除缓存
    indexToHandle.Erase(newIndex);
    newIndexToProviderInfo.Erase(newIndex);

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPin(const std::string &index, const HksBlob &pinData)
{
    std::string providerInfo;
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

    // ret = proxy->VerifyPin(newIndex, handle, pinData);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify pin failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteVerifyPinStatus(const std::string &index)
{
    std::string providerInfo;
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

    // ret = proxy->VerifyPinStatus(newIndex, handle);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify pin status failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteClearPinStatus(const std::string &index)
{
    std::string providerInfo;
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

    // ret = proxy->ClearPinStatus(newIndex, handle);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote clear pin status failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}


int32_t HksRemoteHandleManager::RemoteHandleSign(const std::string &index, const CppParamSet &paramSet,
    const HksBlob &inData, HksBlob &outData)
{
    std::string providerInfo;
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

    // ret = proxy->Sign(newIndex, handle, paramSet, inData, outData);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote sign failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleVerify(const std::string &index, const CppParamSet &极速版paramSet,
    const HksBlob &plainText, HksBlob &signature)
{
    std::string providerInfo;
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

    // ret = proxy->Verify(newIndex, handle, paramSet, plainText, signature);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote verify failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearRemoteHandle()
{
    indexToHandle.Clear();
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ClearKeyHandle(const std::string &abilityName)
{
    if (abilityName.empty()) {
        HKS_LOG_E("Invalid abilityName");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    std::vector<std::string> indexList;
    if (abilityIndexMap.Find(abilityName, indexList) != HKS_SUCCESS) {
        return HKS_SUCCESS;  // 不存在则直接返回成功
    }

    // 删除所有相关的keyHandle
    for (const auto &index : indexList) {
        std::vector<HksBlob> handleList;
        if (indexHandleMap.Find(index, handleList) == HKS_SUCCESS) {
            for (auto& handle : handleList) {
                handleInfoMap.Erase(handle);
                FreeHksBlob(handle);
            }
            indexHandleMap.Erase(index);
        }
    }

    // 删除abilityName的映射
    abilityIndexMap.Erase(abilityName);
    
    // 删除代理对象缓存
    providerProxyMap.Erase(abilityName);
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetHandle(const std::string &abilityName, std::string &index, HksBlob &keyHandle)
{
    auto instance = OHOS::DelayedSingleton<HksRemoteHandleManager>::GetInstance();
    if (instance == nullptr) {
        HKS_LOG_E("Get instance failed");
        return HKS_ERROR_NULL_POINTER;
    }

    // 获取索引
    int32_t ret = instance->GetContainerIndex(abilityName, index);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get container index failed");
        return ret;
    }

    // 查找keyHandle
    CppParamSet paramSet;  // 需要根据实际情况构造paramSet
    return instance->FindKeyHandle(abilityName, index, paramSet, keyHandle);
}

int32_t HksRemoteHandleManager::KeyHandlePreCheck(const std::string &abilityName, std::string &index)
{
    auto instance = OHOS::DelayedSingleton<HksRemoteHandleManager>::GetInstance();
    if (instance == nullptr) {
        HKS_LOG_E("Get instance failed");
        return HKS_ERROR_NULL_POINTER;
    }

    // 检查索引是否存在
    std::vector<std::string> indexList;
    if (instance->abilityIndexMap.Find(abilityName, indexList) != HKS_SUCCESS) {
        return INDEX_NOT_FOUND;
    }

    if (index.empty()) {
        // 如果index为空，返回第一个索引
        if (!indexList.empty()) {
            index = indexList.front();
            return HKS_SUCCESS;
        }
        return INDEX_NOT_FOUND;
    }

    // 检查指定的index是否存在
    if (std::find(indexList.begin(), indexList.end(), index) == indexList.end()) {
        return INDEX_NOT_FOUND;
    }

    return HKS_SUCCESS;
}