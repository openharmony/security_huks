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

#ifndef HKS_REMOTE_HANDLE_MANAGER_H
#define HKS_REMOTE_HANDLE_MANAGER_H

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "singleton.h"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "safe_map.h"

class HksRemoteHandleManager : private OHOS::DelayedSingleton<HksRemoteHandleManager> {
public:
    int32_t CreateKeyHandle(const std::string &abilityName, const std::string &index, const CppParamSet &paramSet);
    
    int32_t FindKeyHandle(const std::string &abilityName, const std::string &index, const CppParamSet &paramSet, HksBlob &keyHandle);

    int32_t CloseKeyHandle(const std::string &abilityName, const std::string &index, const HksBlob &keyHandle);

    int32_t GetContainerIndex(const std::string &abilityName, std::string &index);

    int32_t ClearKeyHandle(const std::string &abilityName);

    static int32_t GetHandle(const std::string &abilityName, std::string &index, HksBlob &keyHandle);

    static int32_t KeyHandlePreCheck(const std::string &abilityName, std::string &index);


private:

    
    // 释放HksBlob资源
    void FreeHksBlob(HksBlob &blob);
    
    int32_t GetRemoteIndex(const std::string &abilityName, std::string &index);
    
    int32_t CreateRemoteHandle(const std::string &abilityName, const std::string &index, 
                              const CppParamSet &paramSet, HksBlob &keyHandle);
    
    OHOS::SafeMap<std::string, std::vector<std::string>> abilityIndexMap;
    
    OHOS::SafeMap<std::string, std::vector<HksBlob>> indexHandleMap;
    
    OHOS::SafeMap<HksBlob, std::pair<std::string, std::string>, HksBlobHash, HksBlobEqual> handleInfoMap;
    
    OHOS::SafeMap<std::string, std::shared_ptr<CrypoExtensionProxy>> providerProxyMap;
};

// HksBlob哈希函数
struct HksBlobHash {
    size_t operator()(const HksBlob& blob) const {
        if (blob.data == nullptr || blob.size == 0) {
            return 0;
        }
        
        // 简单哈希实现，实际可能需要更复杂的哈希函数
        size_t hash = 0;
        for (uint32_t i = 0; i < blob.size; ++i) {
            hash = hash * 31 + blob.data[i];
        }
        return hash;
    }
};

// HksBlob相等比较函数
struct HksBlobEqual {
    bool operator()(const HksBlob& a, const HksBlob& b) const {
        if (a.size != b.size) return false;
        if (a.data == b.data) return true;
        if (a.data == nullptr || b.data == nullptr) return false;
        
        return memcmp(a.data, b.data, a.size) == 0;
    }
};

#endif
#endif