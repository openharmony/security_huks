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

#ifndef HKS_SESSION_MANAGER_H
#define HKS_SESSION_MANAGER_H

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "singleton.h"
#include <memory>
#include <shared_mutex>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "safe_map.h"
#include "ihuks_access_ext_base.h"

namespace OHOS {
namespace Security {
namespace Huks {

struct HandleInfo {
    std::string m_skfSessionHandle;
    ProviderInfo m_providerInfo;
    uint32_t m_uid;
    std::string m_index;
};

class HksSessionManager : private OHOS::DelayedSingleton<HksSessionManager> {
public:
    static std::shared_ptr<HksSessionManager> GetInstanceWrapper();
    static void ReleaseInstance();
    int32_t ExtensionInitSession(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, uint32_t &handle);
    int32_t ExtensionUpdateSession(const HksProcessInfo &processInfo,
        const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
        std::vector<uint8_t> &outData);
    int32_t ExtensionFinishSession(const HksProcessInfo &processInfo,
        const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
        std::vector<uint8_t> &outData);
    int32_t ExtensionAbortSession(const HksProcessInfo &processInfo,
        const uint32_t &handle, const CppParamSet &paramSet);
    bool HksClearHandle(const HksProcessInfo &processInfo, const CppParamSet &paramSet);
    void HksClearHandle(const ProviderInfo &providerInfo);
    bool HksClearHandle(const HksProcessInfo &processInfo, const CppParamSet &paramSet, const std::string &index);
    void ClearSessionMapByHandle(int32_t ret, uint32_t handle);
private:
    int32_t CheckParmSetPurposeAndCheckAuth(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    std::vector<uint32_t> FindToRemoveHandle(const uint32_t &uid, const std::string &abilityName);
    std::vector<uint32_t> FindToRemoveHandle(const uint32_t &uid);
    std::vector<uint32_t> FindToRemoveHandle(const uint32_t &uid, const std::string &abilityName,
        const std::string &index);
    std::vector<uint32_t> FindToRemoveByIndex(const uint32_t &uid, const std::string &index);
    int32_t HksGetHandleInfo(const HksProcessInfo &processInfo, const uint32_t &handle, HandleInfo &infos);
    bool CheckSingleCallerCanInitSession(const HksProcessInfo &processInfo);
    std::pair<int32_t, uint32_t> GenRandomUint32();
    void ClearSessionHandleMap(std::vector<uint32_t> &toRemove);
    OHOS::SafeMap<uint32_t, HandleInfo> m_handlers{};
};

bool CheckAndAppendProcessInfo(CppParamSet &paramSet, const HksProcessInfo &processInfo);
}
}
}

#endif