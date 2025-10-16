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

std::shared_ptr<HuksPluginLifeCycleMgr> HuksPluginLifeCycleMgr::GetInstanceWrapper()
{
    return HuksPluginLifeCycleMgr::GetInstance();
}

void HuksPluginLifeCycleMgr::ReleaseInstance()
{
    HuksPluginLifeCycleMgr::DestroyInstance();
}

int32_t HuksPluginLifeCycleMgr::RegisterProvider(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    int32_t ret;
    int preCount = m_refCount.fetch_add(1, std::memory_order_acq_rel);
    if (preCount == 0) {
        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        HKS_IF_TRUE_LOGE_RETURN(pluginLoader == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get pluginLoader instance.")
        ret = pluginLoader->LoadPlugins(info, providerName, paramSet);
        if (ret != HKS_SUCCESS) {
            m_refCount.fetch_sub(1, std::memory_order_acq_rel);
            HKS_LOG_E("regist provider failed!");
            return ret; 
        }
    }

    auto libInstance = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInstance == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    ret = libInstance->OnRegistProvider(info, providerName, paramSet);
    if (ret != HKS_SUCCESS) {
        m_refCount.fetch_sub(1, std::memory_order_acq_rel);
        HKS_LOG_E("regist provider method in plugin laoder is fail");
        return HKS_ERROR_EXEC_FUNC_FAIL;
    }
    return ret;
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet)
{
    int preCount = m_refCount.fetch_sub(1, std::memory_order_acq_rel);
    auto libInstance = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInstance == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    int32_t ret = libInstance->OnUnRegistProvider(info, providerName, paramSet);
    if (ret != HKS_SUCCESS) {
        m_refCount.fetch_add(1, std::memory_order_acq_rel);
        HKS_LOG_E("unregist provider failed!");
        return HKS_ERROR_CLOSE_PROVIDER_FAIL;
    }

    HKS_IF_TRUE_LOGE_RETURN(preCount != 1, HKS_SUCCESS, "close lib fail, refCount = %{public}d", preCount)

    auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginLoader == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get pluginLoader instance.")
    ret = pluginLoader->UnLoadPlugins(info, providerName, paramSet);
    if (ret != HKS_SUCCESS) {
        m_refCount.fetch_add(1, std::memory_order_acq_rel);
        HKS_LOG_E("close lib failed!, ret = %{public}d", ret);
        return ret; 
    }
    
    HKS_LOG_E("unregist provider success!");
    return HKS_SUCCESS;
}

}
}
}