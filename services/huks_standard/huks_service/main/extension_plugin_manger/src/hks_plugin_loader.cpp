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

#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"

#include <vector>

namespace OHOS::Security::Huks {

std::shared_ptr<HuksPluginLoader> HuksPluginLoader::GetInstanceWrapper()
{
    return HuksPluginLoader::GetInstance();
}

void HuksPluginLoader::ReleaseInstance()
{
    return HuksPluginLoader::DestroyInstance();
}

int32_t HuksPluginLoader::LoadPlugins(const struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet){
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle != nullptr, HKS_SUCCESS)

    m_pluginHandle = dlopen(PLUGIN_SO, RTLD_NOW);
    HKS_IF_NULL_LOGE_RETURN(m_pluginHandle, HKS_ERROR_OPEN_LIB_FAIL,
        "dlopen " PLUGIN_SO " failed! %" LOG_PUBLIC "s", dlerror())

    for (auto i = 0; i < static_cast<int>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            HKS_LOG_E("the entry %{public}s is not include", PLUGIN_SO);
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_FIND_FUNC_MAP_FAIL;
        }

        dlerror();
        void* func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to find entry %{public}s in dynamic link liberary, error is %{public}s",
                methodString.c_str(), dlsym_error);
            dlclose(m_pluginHandle);
            m_pluginHandle= nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_GET_FUNC_POINTER_FAIL;
        }
        m_pluginProviderMap.emplace(std::make_pair(static_cast<PluginMethodEnum>(i), func));
    }

    auto libEntry = HuksLibEntry::GetInstanceWrapper();
    libEntry->initProviderMap(m_pluginProviderMap);

    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::UnLoadPlugins(const struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet) {
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS) //或者换成重复释放的消息码

    m_pluginProviderMap.clear();
    dlclose(m_pluginHandle);
    m_pluginHandle = nullptr;

    return HKS_SUCCESS;
}

std::string HuksPluginLoader::GetMethodByEnum(PluginMethodEnum methodEnum) {
    const auto& it = m_pluginMethodNameMap.find(methodEnum);
    HKS_IF_TRUE_RETURN(it != m_pluginMethodNameMap.end(), it->second)
    HKS_LOG_E("enum = %{public}d can not find string", methodEnum);
    return "";
}

}