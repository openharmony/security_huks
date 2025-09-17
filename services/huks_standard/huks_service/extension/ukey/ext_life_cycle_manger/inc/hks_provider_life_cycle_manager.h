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

#ifndef HKS_PROVIDER_LIFE_CYCLE_MANAGER_H
#define HKS_PROVIDER_LIFE_CYCLE_MANAGER_H

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <securec.h>

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "singleton.h"
#include "safe_map.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Security {
namespace Huks {

class ProviderInfo {
public:
    std::string m_providerName{};
    std::string m_abilityName{};
    std::string m_bundleName{};
};

class HksProviderLifeCycleManager : private OHOS::DelayedSingleton<HksProviderLifeCycleManager> {
public:
    static std::shared_ptr<HksProviderLifeCycleManager> GetInstanceWrapper();
    static void ReleaseInstance();
    int32_t OnRegisterProvider(const HksProcessInfo &processInfo, const std::string &AbilityName,
        const CppParamSet &paramSet);
    int32_t OnUnRegisterProvider(const HksProcessInfo &processInfo, const std::string &AbilityName,
        const CppParamSet &paramSet);
    sptr<IRemoteObject> GetExtensionProxy(const std::string &providerInfo);
private:
    // ProviderName + userId + bundleName
    OHOS::SafeMap<std::string, OHOS::sptr<IRemoteObject>> m_providerMap;
    int32_t GetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
        const CppParamSet &paramSet, ProviderInfo &providerInfo);
};
}
}
}

#endif