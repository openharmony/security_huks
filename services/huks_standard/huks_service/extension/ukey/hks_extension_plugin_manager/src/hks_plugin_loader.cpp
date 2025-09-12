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

#include "hks_extension_plugin_manager.h"
#include "hks_plugin_loader.h"

#include <vector>

namespace OHOS::Security::Huks {

std::shared_ptr<HuksExtensionPluginManager> HuksExtensionPluginManager::GetInstanceWrapper()
{
    return HuksExtensionPluginManager::GetInstance();
}

void HuksExtensionPluginManager::ReleaseInstance()
{
    return HuksExtensionPluginManager::DestroyInstance();
}

int32_t HuksExtensionPluginManager::Start(struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet) {
    int32_t ret = LoadPlugins();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "load plugins fail, ret = %{public}d", ret)

    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::Stop(struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet) {
    int32_t ret = UnLoadPlugins();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "unload plugins fail, ret = %{public}d", ret)
    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::LoadPlugins(){
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle != nullptr, HKS_SUCCESS) //或者换成重复打开的消息码

    m_pluginHandle = dlopen(PLUGIN_SO, RTLD_NOW);
    HKS_IF_NULL_LOGE_RETURN(m_pluginHandle, HKS_ERROR_OPEN_LIB_FAIL,
        "dlopen " PLUGIN_SO " failed! %" LOG_PUBLIC "s", dlerror())

    for (auto i = 0; i < static_cast<int>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            HKS_LOG_E("the entry %{public}d is not include", PLUGIN_SO)
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_FIND_FUNC_MAP_FAIL;
        }
        dlerror();
        void* func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to find entry %{public}d in dynamic link liberary, error is %{public}d",
                methodString.c_str(), dlsym_error)
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_GET_FUNC_POINTER_FAIL;
        }
        m_pluginProviderMap.emplace(std::make_pair(static_cast<PluginMethodEnum>(i), func));
    }

    HuksLibEntry::initProviderMap(m_pluginProviderMap);
    auto libEntry = HuksLibEntry::GetInstanceWrapper();
    
    int32_t ret = libEntry.OnRegistProvider();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_EXEC_FUNC_FAIL,
        "regist provider method in plugin laoder is fail")

    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::UnLoadPlugins() {
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS) //或者换成重复释放的消息码

    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "unregist provider method enum not found in plugin provider map.")
    
    HuksLibEntry::initProviderMap(m_pluginProviderMap);
    auto libEntry = HuksLibEntry::GetInstanceWrapper();
    
    int32_t ret = libEntry.OnUnRegistProvider();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_EXEC_FUNC_FAIL,
        "unregist provider method in plugin laoder is fail")

    m_pluginProviderMap.clear();
    dlclose(m_pluginHandle);
    m_pluginHandle = nullptr;

    return HKS_SUCCESS;
}

std::string HuksExtensionPluginManager::GetMethodByEnum(PluginMethodEnum methodEnum) {
    const auto& it = m_pluginMethodNameMap.find(methodEnum);
    HKS_IF_TRUE_RETURN(it != m_pluginMethodNameMap.end(), it->second)
    HKS_LOG_E("enum = %{public}d can not find string", methodEnum)
    return "";
}

}