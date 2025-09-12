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

#ifndef HKS_PLUGIN_LOADER_H
#define HKS_PLUGIN_LOADER_H

#include <string>
#include <unordered_map>
#include <map>
#include <dlfcn.h>
#include <mutex>
#include <atomic>
#include <cstdint>

#include "hks_lib_interface.h
#include "hks_cpp_paramset.h"
#include "hks_template.h"
#include "singleton.h"
#include "hks_type.h"
#include "hks_plugin_def.h"
#include "hks_service_ipc_serialization.h"
#include "hks_permission_check.h"
#include "hks_response.h"
#include "hks_mem.h"
#include "hks_extension_plugin_manager.h"
#include "safe_map.h"
#include "hks_funtion_types.h"

#define PLUGIN_SO "libhuks_external_crypto_ext_core.z.so"

namespace OHOS {
namespace Security {
namespace Huks {
    class HuksPluginLoader : private OHOS::DelayedSingleton<HuksExtensionPluginManager>{
public:
    std::unordered_map<PluginMethodEnum, void*> m_pluginProviderMap;

    int32_t Start(struct HksProcessInfo &info, const std::string& providerName, const CppParamSet& paramSet);
    int32_t Stop(struct HksProcessInfo &info, const std::string& providerName, const CppParamSet& paramSet);
    static std::shared_ptr<HksProviderLifeCycleManager> GetInstanceWrapper();
    static void ReleaseInstance();
    
private:
    void* m_pluginHandle = nullptr;
    std::atomic<int> m_refCount{0};
    std::mutex libMutex;

    int32_t LoadPlugins(); // TODO:参数根据生命周期模块的注册函数定义
    int32_t UnLoadPlugins(); // TODO:定义
    static std::string GetMethodByEnum(PluginMethodEnum methodEnum);
};
}
}
}
#endif