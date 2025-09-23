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

namespace OHOS {
namespace Security {
namespace Huks {
std::shared_ptr<HuksPluginLifeCycleMgr> HuksPluginLifeCycleMgr::GetInstanceWrapper() {
    return HuksPluginLifeCycleMgr::GetInstance();
}

void HuksPluginLifeCycleMgr::ReleaseInstance()
{
    OHOS::DelayedSingleton<HuksPluginLifeCycleMgr>::DestroyInstance();
}


int32_t HuksPluginLifeCycleMgr::RegisterProvider(const struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet){
    int32_t ret;
    int preCount = m_refCount.fetch_add(1, std::memory_order_acq_rel);
    if (preCount == 0) {
        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        ret = pluginLoader->Start(info, providerName, paramSet);
        if (ret != HKS_SUCCESS) {
            m_refCount.fetch_sub(1, std::memory_order_acq_rel);
            HKS_LOG_E("regist provider failed!");
            return ret; 
        }
    }
    auto libEntry = HuksLibEntry::GetInstanceWrapper();
    ret = libEntry->OnRegistProvider(info, providerName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_EXEC_FUNC_FAIL,
        "regist provider method in plugin laoder is fail")
    RecordProvider(providerName);
    return ret;
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info, const std::string& providerName,
    const CppParamSet& paramSet) {
    int preCount = m_refCount.fetch_sub(1, std::memory_order_acq_rel);
    HKS_IF_TRUE_RETURN(preCount != 1, HKS_SUCCESS)

    auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
    int32_t ret = pluginLoader->Stop(info, providerName, paramSet);
    if (ret != HKS_SUCCESS) {
        m_refCount.fetch_add(1, std::memory_order_acq_rel);
        HKS_LOG_E("unregist provider failed!, ret = %{public}d", ret);
        return ret; 
    }
    return HKS_SUCCESS;
}

void HuksPluginLifeCycleMgr::RecordProvider(const std::string &providerName) {
    //TODO:需要区分是否为重复注册的provider吗
    //auto ret = registerProvider.Add(providerName);
    //HKS_IF_TRUE_LOGI_RETURN_VOID(!ret, "repete record provider")
}

}
}
}