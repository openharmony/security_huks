
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
                                                         ProviderInfo &providerInfo, 
                                                         std::string &newIndex)
{
    CommJsonObject root = CommJsonObject::Parse(index);
    if (root.IsNull()) {
        HKS_LOG_E("Parse index failed, invalid JSON format");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    auto providerNameObj = root.GetValue(PROVIDER_NAME_KEY);
    auto providerNameResult = providerNameObj.ToString();
    
    auto abilityNameObj = root.GetValue(ABILITY_NAME_KEY);
    auto abilityNameResult = abilityNameObj.ToString();
    
    auto bundleNameObj = root.GetValue(BUNDLE_NAME_KEY);
    auto bundleNameResult = bundleNameObj.ToString();
    
    if (providerNameResult.first != HKS_SUCCESS || abilityNameResult.first != HKS_SUCCESS || 
        bundleNameResult.first != HKS_SUCCESS) {
        HKS_LOG_E("Get provider info fields failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    providerInfo.m_providerName = providerNameResult.second;
    providerInfo.m_abilityName = abilityNameResult.second;
    providerInfo.m_bundleName = bundleNameResult.second;
    
    if (providerInfo.m_providerName.empty() || providerInfo.m_abilityName.empty() || 
        providerInfo.m_bundleName.empty()) {
        HKS_LOG_E("Provider info is incomplete");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    CommJsonObject newRoot = CommJsonObject::CreateObject();

    auto keys = root.GetKeys();
    for (const auto &key : keys) {
        if (key != PROVIDER_NAME_KEY && key != ABILITY_NAME_KEY && key != BUNDLE_NAME_KEY) {
            auto value = root.GetValue(key);
            if (value.IsNull()) {
                HKS_LOG_W("Skip invalid field: %s", key.c_str());
                continue;
            }
            
            if (!newRoot.SetValue(key, value)) {
                HKS_LOG_E("Copy field %s failed", key.c_str());
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

int32_t HksRemoteHandleManager::ValidateProviderInfo(const std::string &newIndex, const ProviderInfo &providerInfo)
{
    ProviderInfo cachedProviderInfo;
    if (!newIndexToProviderInfo.Find(newIndex, cachedProviderInfo)) {
        HKS_LOG_E("Provider info not found for newIndex: %s", newIndex.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    
    if (!(cachedProviderInfo == providerInfo)) {
        HKS_LOG_E("Provider info mismatch");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    return HKS_SUCCESS;
}

OHOS::sptr<IHuksAccessExtBase> HksRemoteHandleManager::GetProviderProxy(const ProviderInfo &providerInfo, int32_t &ret)
{
    auto providerManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerManager == nullptr) {
        HKS_LOG_E("Get provider manager instance failed");
        ret = HKS_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }

    sptr<IHuksAccessExtBase> proxy;
    ret = providerManager->GetExtensionProxy(providerInfo, proxy);
    if (ret != HKS_SUCCESS || proxy == nullptr) {
        HKS_LOG_E("Get extension proxy failed for provider: %s", providerInfo.m_providerName.c_str());
        ret = HKS_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    
    ret = HKS_SUCCESS;
    return proxy;
}

int32_t HksRemoteHandleManager::GetRemoteIndex(const ProviderInfo &providerInfo, [[maybe_unused]] const CppParamSet &paramSet, std::string &index)
{
    CommJsonObject root = CommJsonObject::CreateObject();
    
    if (!root.SetValue(PROVIDER_NAME_KEY, providerInfo.m_providerName) ||
        !root.SetValue(ABILITY_NAME_KEY, providerInfo.m_abilityName) ||
        !root.SetValue(BUNDLE_NAME_KEY, providerInfo.m_bundleName)) {
        HKS_LOG_E("Set provider info to index failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    
    
    index = root.Serialize(false);
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::ValidateAndGetHandle(const std::string &newIndex, 
                                                    const ProviderInfo &providerInfo, std::string &handle)
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

    // 这里调用远程provider的创建handle方法
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

    // 调用远程provider的关闭handle方法
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

    // 调用远程provider的验证PIN方法
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

    // 调用远程provider的验证PIN状态方法
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
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleSign(const std::string &index, const CppParamSet &paramSet,
    const HksBlob &inData, HksBlob &outData)
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

    // 调用远程provider的签名方法
    // ret = proxy->Sign(newIndex, handle, paramSet, inData, outData);
    ret = HKS_SUCCESS;
    
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Remote sign failed: %d", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::RemoteHandleVerify(const std::string &index, const CppParamSet &paramSet,
    const HksBlob &plainText, HksBlob &signature)
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

    // 调用远程provider的验签方法
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
    newIndexToProviderInfo.Clear();
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