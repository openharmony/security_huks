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

#define NO_EXTENSION 0
#define ONE_EXTENSION 1
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
    std::unique_lock<std::mutex> lock(soMutex);
    int32_t preCount = m_refCount.fetch_add(1, std::memory_order_acq_rel);
    if (preCount == NO_EXTENSION) {
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
        HKS_LOG_E("regist provider method in plugin loader is fail");
        return ret;
    }
    return ret;
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet)
{
    std::unique_lock<std::mutex> lock(soMutex);
    if (m_refCount.load() == NO_EXTENSION) {
        HKS_LOG_I("lib has closed!");
        return HKS_ERROR_LIB_REPEAT_CLOSE;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        auto libInstance = HuksLibInterface::GetInstanceWrapper();
        if (libInstance == nullptr) {
            ret = HKS_ERROR_NULL_POINTER;
            HKS_LOG_E("Failed to get LibInterface instance.");
            break;
        }

        ret = libInstance->OnUnRegistProvider(info, providerName, paramSet);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "unregist provider failed! ret = %{public}d", ret)

        HKS_IF_TRUE_LOGE_BREAK(m_refCount.load() != ONE_EXTENSION,
            "don't need close lib, refCount = %{public}d", m_refCount.load())

        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        if (pluginLoader == nullptr) {
            ret = HKS_ERROR_NULL_POINTER;
            HKS_LOG_E("Failed to get pluginLoader instance.");
            break;
        }

        ret = pluginLoader->UnLoadPlugins(info, providerName, paramSet);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "close lib failed!, ret = %{public}d", ret)
    } while (0);

    if (ret == HKS_SUCCESS) {
        m_refCount.fetch_sub(1, std::memory_order_acq_rel);
        HKS_LOG_I("unregist provider success!");
        return HKS_SUCCESS;
    }

    return ret;
}

}
}
}