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
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "safe_map.h"
#include "ihuks_access_ext_base.h"

namespace OHOS {
namespace Security {
namespace Huks {
class HksSessionManager : private OHOS::DelayedSingleton<HksSessionManager> {
public:
    std::pair<int32_t, uint32_t> GenRandomUint32();
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
private:
    OHOS::SafeMap<uint32_t, std::pair<ProviderInfo, std::string>> handlers_;
};
}
}
}

#endif