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

#ifndef HKS_PLUGIN_LIFECYCLE_MANAGER_H
#define HKS_PLUGIN_LIFECYCLE_MANAGER_H

#include <atomic>
#include <string>
#include <memory>
#include <map>
#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_plugin_def.h"
#include "singleton.h"
#include "hks_template.h"
#include "hks_function_types.h"


namespace OHOS {
namespace Security {
namespace Huks {
class __attribute__((visibility("default"))) HuksPluginLifeCycleMgr :
    private OHOS::DelayedSingleton<HuksPluginLifeCycleMgr> {
public:
    static std::shared_ptr<HuksPluginLifeCycleMgr> GetInstanceWrapper();
    static void ReleaseInstance();
    int32_t RegisterProvider(const struct HksProcessInfo &info, const std::string &AbilityName,
        const CppParamSet &paramSet);
    int32_t UnRegisterProvider(const struct HksProcessInfo &info, const std::string &AbilityName,
        const CppParamSet &paramSet);

private:
    std::atomic<int> m_refCount{0};
    static HuksPluginLifeCycleMgr instancePLCM;
};

}
}
}
#endif