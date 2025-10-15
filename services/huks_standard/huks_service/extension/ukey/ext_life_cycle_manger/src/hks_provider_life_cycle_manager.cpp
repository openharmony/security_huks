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
#include "hks_cpp_paramset.h"
#include "if_system_ability_manager.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_info.h"
#include "system_ability_definition.h"
#include <iservice_registry.h>
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_template.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "refbase.h"
#include <memory>
#include <string>

namespace OHOS::Security::Huks {

bool ProviderInfo::operator==(const ProviderInfo &other) const
{
    return m_bundleName == other.m_bundleName && m_providerName == other.m_providerName && 
        m_abilityName == other.m_abilityName;
}

bool ProviderInfo::operator<(const ProviderInfo &other) const
{
    return m_providerName < other.m_providerName;
}

std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    HksProviderLifeCycleManager::DestroyInstance();
}

constexpr int32_t HKS_MAX_PROVIDER_NUM = 20;
int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    HKS_LOG_I("OnRegisterProvider providerName: %" LOG_PUBLIC "s", providerName.c_str());
    if (m_providerMap.Size() > HKS_MAX_PROVIDER_NUM) {
        HKS_LOG_E("OnRegisterProvider failed, providerNum is too much."
            "providerNum: %" LOG_PUBLIC "d", m_providerMap.Size());
        return HKS_ERROR_UKY_PROVIDER_MGR_REGESTER_REACH_MAX_NUM;
    }
    ProviderInfo providerInfo{};
    int32_t ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_NULL_POINTER, "Fail to get provider info")

    std::shared_ptr<HksExtAbilityConnectInfo> connectInfo{nullptr};
    if (!m_providerMap.Find(providerInfo, connectInfo)) {
        AAFwk::Want want{};
        want.SetElementName(providerInfo.m_bundleName, providerInfo.m_abilityName);
        sptr<ExtensionConnection> connect(new (std::nothrow) ExtensionConnection());
        HKS_IF_TRUE_LOGE_RETURN(connect == nullptr, HKS_ERROR_NULL_POINTER, "new ExtensionConnection failed");

        if (!connect->IsConnected()) {
            HKS_LOG_I("First time connect the Extension Ability. "
                "m_bundleName: %" LOG_PUBLIC "s, m_abilityName: %" LOG_PUBLIC "s",
                providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str());
            connect->OnConnection(want);
        }

        auto proxy = connect->GetExtConnectProxy();
        HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NULL_POINTER, "connected, bug getExtConnectProxy failed.");

        connectInfo = std::make_shared<HksExtAbilityConnectInfo>(want, connect);
        m_providerMap.Insert(providerInfo, connectInfo);
        HKS_LOG_I("OnRegisterProvider Success! providerName: %" LOG_PUBLIC "s", providerName.c_str());
        ret = HKS_SUCCESS;
    } else {
        HKS_LOG_E("OnRegisterProvider failed, providerName: %" LOG_PUBLIC "s, already exist", providerName.c_str());
        ret = HKS_ERROR_ALREADY_EXISTS;
    }
    return ret;
}

int32_t HksProviderLifeCycleManager::GetExtensionProxy(const ProviderInfo &providerInfo,
    sptr<IHuksAccessExtBase> &proxy)
{
    std::shared_ptr<HksExtAbilityConnectInfo> connectionInfo = nullptr;
    if(!m_providerMap.Find(providerInfo, connectionInfo)) {
        HKS_LOG_E("GetExtensionProxy failed, providerName: %s", providerInfo.m_providerName.c_str());
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_IF_TRUE_LOGE_RETURN(connectionInfo == nullptr, HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
    HKS_IF_TRUE_LOGE_RETURN(connectionInfo->m_connection == nullptr, HKS_ERROR_NULL_POINTER, "m_connection is nullptr")
    proxy = connectionInfo->m_connection->GetExtConnectProxy();
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetAllConnectInfoByProviderName(const HksProcessInfo &processInfo, const std::string &providerName,
    std::vector<std::shared_ptr<HksExtAbilityConnectInfo>> &providerInfos)
{
    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(saMgr, HKS_ERROR_NULL_POINTER, "GetSystemAbilityManager failed")

    sptr<IRemoteObject> remoteObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "GetSystemAbility failed")

    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "iface_cast IBundleMgr failed")

    std::string bundleName;
    auto bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(processInfo.uidInt), bundleName);
    HKS_IF_TRUE_LOGE_RETURN(!bundleRet, HKS_ERROR_BAD_STATE, "GetBundleNameForUid failed")

    m_providerMap.Iterate([&](const ProviderInfo &providerInfo, std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        if (providerInfo.m_bundleName == bundleName && providerInfo.m_providerName == providerName) {
            providerInfos.push_back(connectionInfo);
        }
    });
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet)
{
    std::shared_ptr<HksExtAbilityConnectInfo> connectionInfo = nullptr;
    ProviderInfo providerInfo{};
    int32_t ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_NULL_POINTER, "Fail to get provider info")

    std::vector<std::shared_ptr<HksExtAbilityConnectInfo>> connectionInfos;
    ret = GetAllConnectInfoByProviderName(processInfo, providerName, connectionInfos);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "Fail to get provider infos")
    if (connectionInfos.empty()) {
        HKS_LOG_E("OnUnRegisterProvider failed, unfound provider connections. providerName: %s", providerName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    for (auto &connectionInfo : connectionInfos) {
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo == nullptr, HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo->m_connection == nullptr, HKS_ERROR_NULL_POINTER, "m_connection is nullptr")
    
        auto proxy = connectionInfo->m_connection->GetExtConnectProxy();
        HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NULL_POINTER, "GetExtConnectProxy failed");
    
        int32_t refCount = proxy->GetSptrRefCount();
        HKS_LOG_I("OnUnRegisterProvider connection want abilityName: %" LOG_PUBLIC "s",
            connectionInfo->m_want.GetElement().GetAbilityName().c_str());
        HKS_LOG_I("OnUnRegisterProvider refCount: %" LOG_PUBLIC "d", refCount);
        if (refCount > HKS_PROVIDER_CAN_REMOVE_REF_COUNT) {
            HKS_LOG_E("OnUnRegisterProvider failed, refCount is not 2, maybe in use.");
            return HKS_ERROR_BAD_STATE;
        }
        connectionInfo->m_connection->OnDisconnect();
        m_providerMap.Erase(providerInfo);
    }
    HKS_LOG_I("OnUnRegisterProvider Success! providerName: %" LOG_PUBLIC "s", providerName.c_str());
    return HKS_SUCCESS;
}

int32_t HksGetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, ProviderInfo &providerInfo)
{
    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(saMgr, HKS_ERROR_NULL_POINTER, "GetSystemAbilityManager failed")

    sptr<IRemoteObject> remoteObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "GetSystemAbility failed")

    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "iface_cast IBundleMgr failed")

    auto bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(processInfo.uidInt), providerInfo.m_bundleName);
    HKS_IF_TRUE_LOGE_RETURN(!bundleRet, HKS_ERROR_BAD_STATE, "GetBundleNameForUid failed")
    providerInfo.m_providerName = providerName;

    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    HKS_IF_TRUE_LOGE_RETURN(abilityName.first != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "GetParam HKS_EXT_CRYPTO_TAG_ABILITY_NAME failed")
    providerInfo.m_abilityName = std::string(abilityName.second.begin(), abilityName.second.end());
    return HKS_SUCCESS;
}

}