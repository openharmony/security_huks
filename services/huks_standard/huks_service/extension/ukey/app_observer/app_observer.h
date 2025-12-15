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

#ifndef HKS_APP_OBSERVER_H
#define HKS_APP_OBSERVER_H

#include <atomic>
#include <string>
#include <mutex>
#include <map>
#include "application_state_observer_stub.h"
#include "iremote_object.h"
#include "hks_cpp_paramset.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"

namespace OHOS {
namespace Security {
namespace Huks {

struct HksProcessContext {
    uint32_t uidInt;
    std::string abilityName;

    HksProcessContext(const HksProcessInfo &info, const CppParamSet &paramSet)
        : uidInt(info.uidInt)
    {
        auto result = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
        if (result.first == HKS_SUCCESS && !result.second.empty()) {
            if (result.second.size() >= MAX_ABILITY_NAME_LEN) {
                HKS_LOG_E("HksProcessContext: abilityName too long, size: %{public}zu", result.second.size());
                abilityName = "";
            } else {
                abilityName = std::string(result.second.begin(), result.second.end());
            }
        } else {
            HKS_LOG_E("HksProcessContext: fail get abilityName in paramSet");
            abilityName = "";
        }
    }
};

class HksAppObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    explicit HksAppObserver(const std::string &bundleName);
    ~HksAppObserver() override = default;

    void OnAppStopped(const AppExecFwk::AppStateData &appStateData) override;
    void AddProcessContext(const HksProcessInfo &processInfo, const CppParamSet &paramSet);
    const std::string& GetBundleName() const { return targetBundleName_; }

private:
    CppParamSet BuildParamSet(const HksProcessContext &context);

    const std::string targetBundleName_;

    mutable std::mutex mutex_;
    std::map<uint32_t, HksProcessContext> uidToContextMap_;
};

class HksAppObserverManager {
public:
    static HksAppObserverManager& GetInstance();

    DISALLOW_COPY_AND_MOVE(HksAppObserverManager);

    int32_t RegisterObserver(const HksProcessInfo &processInfo, const CppParamSet &paramSet);
    void CleanupTriggeredObserver(const std::string &bundleName);
    int32_t UnregisterAllObservers();

private:
    HksAppObserverManager() = default;
    ~HksAppObserverManager() = default;

    int32_t GetBundleNameByUid(uint32_t uid, std::string &bundleName);

    std::mutex mutex_{};
    std::map<std::string, sptr<HksAppObserver>> observers_{};
};
}
}
}
#endif // HKS_APP_OBSERVER_H