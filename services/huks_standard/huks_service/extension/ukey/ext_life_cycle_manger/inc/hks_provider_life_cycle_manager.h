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
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <securec.h>
#include <unordered_set>

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "singleton.h"
#include "safe_map.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "want.h"
#include "hks_extension_connection.h"
#include "ihuks_access_ext_base.h"

namespace OHOS {
namespace Security {
namespace Huks {

class ProviderInfo {
public:
    std::string m_providerName{};
    std::string m_abilityName{};
    std::string m_bundleName{};

    bool operator==(const ProviderInfo &other) const;
    bool operator<(const ProviderInfo &other) const;
};

class HksExtAbilityConnectInfo {
public:
    HksExtAbilityConnectInfo(const AAFwk::Want &want, const sptr<ExtensionConnection> &connection)
        : m_want(want), m_connection(connection) {};
    ~HksExtAbilityConnectInfo() = default;
    AAFwk::Want m_want{};
    sptr<ExtensionConnection> m_connection{nullptr};
};

constexpr int32_t HKS_PROVIDER_CAN_REMOVE_REF_COUNT = 2;
int32_t HksGetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, ProviderInfo &providerInfo);

class HksProviderLifeCycleManager : private OHOS::DelayedSingleton<HksProviderLifeCycleManager>,
    std::enable_shared_from_this<HksProviderLifeCycleManager> {
public:
    static std::shared_ptr<HksProviderLifeCycleManager> GetInstanceWrapper();
    static void ReleaseInstance();
    int32_t OnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName,
        const CppParamSet &paramSet);
    int32_t OnUnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName,
        const CppParamSet &paramSet);
    int32_t GetExtensionProxy(const ProviderInfo &providerInfo, sptr<IHuksAccessExtBase> &proxy);

    int32_t GetAllConnectInfoByProviderName(const HksProcessInfo &processInfo, const std::string &providerName,
        std::vector<std::shared_ptr<HksExtAbilityConnectInfo>> &providerInfos);
    int32_t GetAllProviderInfosByProviderName(const std::string &providerName,
        std::vector<ProviderInfo> &providerInfos);
private:
    // ProviderInfo, connectionInfo
    OHOS::SafeMap<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>> m_providerMap{};
};
}
}
}

#endif