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


inline void FreeHksBlob(HksBlob *&blob)
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

inline HksBlob StringToBlob(const std::string &inStr)
{
    return {
        .size = inStr.size(),
        .data = reinterpret_cast<uint8_t *>(const_cast<char *>(inStr.c_str())),
    };
}

namespace {
constexpr uint32_t MAX_INDEX_NUM = 1000;
constexpr int32_t INDEX_NOT_FOUND = -1;
constexpr int32_t HANDLE_NOT_FOUND = -2;
}  // namespace


int32_t HksRemoteHandleManager::CopyHksBlob(const HksBlob &src, HksBlob &dest)
{
    if (src.size == 0 || src.data == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }

    uint8_t *data = static_cast<uint8_t *>(HksMalloc(src.size));
    if (data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(data, src.size, src.data, src.size);
    dest.data = data;
    dest.size = src.size;
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetRemoteIndex(const std::string &abilityName, std::string &index)
{
    
    auto providerManager = HksProviderLifeCycleManager::GetInstanceWrapper();
    if (providerManager == nullptr) {
        HKS_LOG_E("Get provider manager instance failed");
        return HKS_ERROR_NULL_POINTER;
    }
    
    auto proxy = providerManager->GetExtensionProxy(abilityName);
    if (proxy == nullptr) {
        HKS_LOG_E("Get extension proxy failed for ability: %s", abilityName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    
    // 缓存代理对象
    if (!providerProxyMap.Insert(abilityName, proxy)) {
        HKS_LOG_E("Cache provider proxy failed");
        return HKS_FAILURE;
    }
    
    // int32_t ret = proxy->GetRemoteIndex(index);
    // if (ret != HKS_SUCCESS) {
    //     HKS_LOG_E("Get remote index failed: %d", ret);
    //     return ret;
    // }
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateRemoteHandle(const std::string &abilityName, const std::string &index, 
                                                  const CppParamSet &paramSet, HksBlob &keyHandle)
{
    std::shared_ptr<CrypoExtensionProxy> proxy;
    if (providerProxyMap.Find(abilityName, proxy) != HKS_SUCCESS) {
        HKS_LOG_E("Get cached proxy failed for ability: %s", abilityName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    
    // std::string remoteHandle;
    // int32_t ret = proxy->CreateRemoteHandle(index, paramSet, remoteHandle);
    // if (ret != HKS_SUCCESS) {
    //     HKS_LOG_E("Create remote handle failed: %d", ret);
    //     return ret;
    // }
    
    std::string remoteHandle = "remote_handle_" + GenerateRandomIndex();
    HKS_LOG_I("Create remote handle success: %s", remoteHandle.c_str());
    
    keyHandle.size = remoteHandle.size();
    keyHandle.data = static_cast<uint8_t *>(HksMalloc(keyHandle.size));
    if (keyHandle.data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    
    (void)memcpy_s(keyHandle.data, keyHandle.size, remoteHandle.data(), remoteHandle.size());
    
    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::CreateKeyHandle(const std::string &abilityName, const std::string &index, 
                                               const CppParamSet &paramSet)
{
    if (abilityName.empty() || index.empty()) {
        HKS_LOG_E("Invalid abilityName or index");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    HksBlob keyHandle = {0, nullptr};
    int32_t ret = CreateRemoteHandle(abilityName, index, paramSet, keyHandle);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Create remote handle failed: %d", ret);
        return ret;
    }

    std::vector<HksBlob> handleList;
    if (indexHandleMap.Find(index, handleList) != HKS_SUCCESS) {
        handleList = {keyHandle};
    } else {
        handleList.push_back(keyHandle);
    }
    
    if (!indexHandleMap.Insert(index, handleList)) {
        FreeHksBlob(keyHandle);
        HKS_LOG_E("Insert key handle failed");
        return HKS_FAILURE;
    }

    // 存储句柄到能力名和索引的映射
    if (!handleInfoMap.Insert(keyHandle, std::make_pair(abilityName, index))) {
        HKS_LOG_E("Insert handle info failed");
        handleList.erase(std::remove(handleList.begin(), handleList.end(), keyHandle), handleList.end());
        if (handleList.empty()) {
            indexHandleMap.Erase(index);
        } else {
            indexHandleMap.Insert(index, handleList);
        }
        FreeHksBlob(keyHandle);
        return HKS_FAILURE;
    }

    std::vector<std::string> indexList;
    if (abilityIndexMap.Find(abilityName, indexList) != HKS_SUCCESS) {
        indexList = {index};
    } else {
        if (std::find(indexList.begin(), indexList.end(), index) == indexList.end()) {
            indexList.push_back(index);
        }
    }

    if (!abilityIndexMap.Insert(abilityName, indexList)) {
        HKS_LOG_E("Update ability index list failed");
        handleList.erase(std::remove(handleList.begin(), handleList.end(), keyHandle), handleList.end());
        if (handleList.empty()) {
            indexHandleMap.Erase(index);
        } else {
            indexHandleMap.Insert(index, handleList);
        }
        handleInfoMap.Erase(keyHandle);
        FreeHksBlob(keyHandle);
        return HKS_FAILURE;
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::FindKeyHandle(const std::string &abilityName, const std::string &index,
                                             const CppParamSet &paramSet, HksBlob &keyHandle)
{
    if (abilityName.empty() || index.empty()) {
        HKS_LOG_E("Invalid abilityName or index");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    std::vector<HksBlob> handleList;
    if (indexHandleMap.Find(index, handleList) != HKS_SUCCESS) {
        HKS_LOG_E("Key handle not found for index: %s", index.c_str());
        return HKS_ERROR_NOT_EXIST;
    }

    if (!handleList.empty()) {
        std::pair<std::string, std::string> info;
        if (handleInfoMap.Find(handleList[0], info) == HKS_SUCCESS && info.first == abilityName) {
            return CopyHksBlob(handleList[0], keyHandle);
        }
    }

    HKS_LOG_E("Key handle not found for ability: %s, index: %s", abilityName.c_str(), index.c_str());
    return HKS_ERROR_NOT_EXIST;
}

int32_t HksRemoteHandleManager::CloseKeyHandle(const std::string &abilityName, const std::string &index,
                                              const HksBlob &keyHandle)
{
    // 检查abilityName和index是否有效
    if (abilityName.empty() || index.empty()) {
        HKS_LOG_E("Invalid abilityName or index");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // 验证句柄对应的信息是否匹配
    std::pair<std::string, std::string> info;
    if (handleInfoMap.Find(keyHandle, info) != HKS_SUCCESS) {
        HKS_LOG_E("Key handle not found");
        return HKS_ERROR_NOT_EXIST;
    }

    if (info.first != abilityName || info.second != index) {
        HKS_LOG_E("AbilityName or index not match");
        return HKS_ERROR_NOT_EXIST;
    }

    // 从索引到句柄的映射中移除
    std::vector<HksBlob> handleList;
    if (indexHandleMap.Find(index, handleList) == HKS_SUCCESS) {
        auto it = std::remove(handleList.begin(), handleList.end(), keyHandle);
        if (it != handleList.end()) {
            handleList.erase(it, handleList.end());
            
            if (handleList.empty()) {
                indexHandleMap.Erase(index);
            } else {
                indexHandleMap.Insert(index, handleList);
            }
        }
    }

    // 从句柄到信息的映射中移除
    handleInfoMap.Erase(keyHandle);

    // 如果该index已经没有句柄，从abilityIndexMap中移除
    if (handleList.empty()) {
        std::vector<std::string> indexList;
        if (abilityIndexMap.Find(abilityName, indexList) == HKS_SUCCESS) {
            auto indexIt = std::find(indexList.begin(), indexList.end(), index);
            if (indexIt != indexList.end()) {
                indexList.erase(indexIt);
                if (indexList.empty()) {
                    abilityIndexMap.Erase(abilityName);
                } else {
                    abilityIndexMap.Insert(abilityName, indexList);
                }
            }
        }
    }

    return HKS_SUCCESS;
}

int32_t HksRemoteHandleManager::GetContainerIndex(const std::string &abilityName, std::string &index)
{
    if (abilityName.empty()) {
        HKS_LOG_E("Invalid abilityName");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // 检查是否已存在索引
    std::vector<std::string> indexList;
    if (abilityIndexMap.Find(abilityName, indexList) == HKS_SUCCESS) {
        if (!indexList.empty()) {
            index = indexList.front();
            return HKS_SUCCESS;
        }
    }

    // 通过代理对象获取远程索引
    int32_t ret = GetRemoteIndex(abilityName, index);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Get remote index failed: %d", ret);
        return ret;
    }

    // 缓存索引
    if (indexList.empty()) {
        indexList = {index};
    } else {
        indexList.push_back(index);
    }
    
    if (!abilityIndexMap.Insert(abilityName, indexList)) {
        HKS_LOG_E("Cache index failed");
        return HKS_FAILURE;
    }

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