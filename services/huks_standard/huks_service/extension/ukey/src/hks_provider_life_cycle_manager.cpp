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

std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    return HksProviderLifeCycleManager::DestroyInstance();
}

static std::shared_ptr<CrypoExtensionProxy> TO_REMOV_Connect(){
    return std::make_shared<CrypoExtensionProxy>();
}

int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    // TODO: ConnetExtension
    m_providerMap.Insert(providerName, TO_REMOV_Connect());
    return HKS_SUCCESS;
}

std::shared_ptr<CrypoExtensionProxy> HksProviderLifeCycleManager::GetExtensionProxy(const std::string &providerName,
    const HksProcessInfo &processInfo)
{
    std::shared_ptr<CrypoExtensionProxy> retProxy = nullptr;
    if(!m_providerMap.Find(providerName, retProxy)) {
        HKS_LOG_E("GetExtensionProxy failed, providerName: %s", providerName.c_str());
        return nullptr;
    }
    return retProxy;
}