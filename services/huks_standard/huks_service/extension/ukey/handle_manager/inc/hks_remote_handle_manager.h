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

    static std::shared_ptr<HksRemoteHandleManager> GetInstanceWrapper();
    static void ReleaseInstance();

    int32_t GetRemoteIndex(const ProviderInfo &providerInfo, [[maybe_unused]] const CppParamSet &paramSet, std::string &index);
    // handle管理
    int32_t CreateRemoteHandle(const std::string &index, [[maybe_unused]] const CppParamSet &paramSet);
    int32_t CloseRemoteHandle(const std::string &index, [[maybe_unused]] const CppParamSet &paramSet);

    // ukey PIN码管理
    int32_t RemoteVerifyPin(const std::string &index, const HksBlob &pinData);
    int32_t RemoteVerifyPinStatus(const std::string &index);
    int32_t RemoteClearPinStatus(const std::string &index);

    //证书查询
    //  int32_t FindRemoteCertificate(const std::string &index, const std::string certificatesOut);
    // int32_t FindRemoteAllCertificate(const std::string &index, const std::string certificatesOut);

    //签名验签
    int32_t RemoteHandleSign(const std::string &index, const CppParamSet &paramSet,
            const HksBlob &inData, HksBlob &outData);
    int32_t RemoteHandleVerify(const std::string &index, const CppParamSet &paramSet,
            const HksBlob &plainText, HksBlob &signature);


    int32_t ClearRemoteHandle();

    static int32_t ParseIndexAndProviderInfo(const std::string &index, ProviderInfo &providerInfo, std::string &newIndex);

    int32_t ValidateProviderInfo(const std::string &newIndex, const ProviderInfo &providerInfo);

private:

    int32_t ValidateAndGetHandle(const std::string &newIndex, const ProviderInfo &providerInfo, std::string &handle);
    int32_t ParseAndValidateIndex(const std::string &index, ProviderInfo &providerInfo,
                                    std::string &newIndex,std::string &handle);
    OHOS::sptr<IRemoteObject> GetProviderProxy(const ProviderInfo &providerInfo, int32_t &ret);

    OHOS::SafeMap<std::string, std::string> indexToHandle;

    OHOS::SafeMap<std::string, ProviderInfo> newIndexToProviderInfo;
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