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

#include "hks_provider_life_cycle_manager.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include <memory>

namespace OHOS::Security::Huks {

std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    return HksProviderLifeCycleManager::DestroyInstance();
}

int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet)
{
    // TODO: ConnetExtension and get the sptr<IRemoteObject>
    return HKS_SUCCESS;
}

OHOS::sptr<IRemoteObject> HksProviderLifeCycleManager::GetExtensionProxy(const std::string &providerName,
    [[maybe_unused]] const HksProcessInfo &processInfo)
{
    sptr<IRemoteObject> retProxy = nullptr;
    if(!m_providerMap.Find(providerName, retProxy)) {
        HKS_LOG_E("GetExtensionProxy failed, providerName: %s", providerName.c_str());
        return nullptr;
    }
    return retProxy;
}

int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet)
{
    sptr<IRemoteObject> retProxy = nullptr;
    if(!m_providerMap.Find(providerName, retProxy)) {
        HKS_LOG_E("OnUnRegisterProvider failed, unfound providerName: %s", providerName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    m_providerMap.Erase(providerName);
    return HKS_SUCCESS;
}
}