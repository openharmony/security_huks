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
#include "hks_ukey_common.h"
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
#include <tuple>
#include <utility>
#include <chrono>
#include <thread>
namespace OHOS::Security::Huks {

bool ProviderInfo::operator==(const ProviderInfo &other) const
{
    return m_bundleName == other.m_bundleName && m_providerName == other.m_providerName &&
        m_abilityName == other.m_abilityName;
}

bool ProviderInfo::operator<(const ProviderInfo &other) const
{
    return std::tie(m_bundleName, m_providerName, m_abilityName) <
        std::tie(other.m_bundleName, other.m_providerName, other.m_abilityName);
}

std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    HksProviderLifeCycleManager::DestroyInstance();
}
void HksProviderLifeCycleManager::PrintRegisterProviders()
{
    HKS_LOG_I("All m_providerMap size: %" LOG_PUBLIC "d", m_providerMap.Size());
    m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
        std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        HKS_LOG_I("m_providerInfo: %" LOG_PUBLIC "s, m_abilityName: %" LOG_PUBLIC "s, m_bundleName: %" LOG_PUBLIC "s",
            providerInfo.m_providerName.c_str(), providerInfo.m_abilityName.c_str(), providerInfo.m_bundleName.c_str());
    });
}

int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(bool)> callback)
{
    HKS_LOG_I("OnRegisterProvider providerName: %" LOG_PUBLIC "s", providerName.c_str());
    HKS_IF_TRUE_RETURN(!CheckStringParamLenIsOk(providerName, 1, MAX_PROVIDER_NAME_LEN), HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_LOGE_RETURN(m_providerMap.Size() >= HKS_MAX_PROVIDER_NUM,
        HKS_ERROR_UKY_PROVIDER_MGR_REGESTER_REACH_MAX_NUM, "OnRegisterProvider failed, providerNum is too much.")
    ProviderInfo providerInfo{};
    int32_t ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Fail to get provider info. providerName: %" LOG_PUBLIC "s. ret: %" LOG_PUBLIC "d", providerName.c_str(), ret)
    HKS_LOG_I("bundleName: %" LOG_PUBLIC "s, abilityName: %" LOG_PUBLIC "s",
        providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str());
    std::shared_ptr<HksExtAbilityConnectInfo> connectInfo{nullptr};
    std::lock_guard<std::mutex> lock(m_registerMutex);
    this->PrintRegisterProviders();
    if (!m_providerMap.Find(providerInfo, connectInfo)) {
        AAFwk::Want want{};
        want.SetElementName(providerInfo.m_bundleName, providerInfo.m_abilityName);
        sptr<ExtensionConnection> connect(new (std::nothrow) ExtensionConnection());
        connect->callBackFromPlugin(callback);
        HKS_IF_TRUE_LOGE_RETURN(connect == nullptr, HKS_ERROR_NULL_POINTER, "new ExtensionConnection failed");

        if (!connect->IsConnected()) {
            HKS_LOG_I("First time connect the Extension Ability. "
                "m_bundleName: %" LOG_PUBLIC "s, m_abilityName: %" LOG_PUBLIC "s",
                providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str());
            ret = connect->OnConnection(want, connect);
            HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "Connect extAbility failed. ret: %" LOG_PUBLIC "d", ret)
        }

        auto proxy = connect->GetExtConnectProxy();
        HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NULL_POINTER, "connected, but getExtConnectProxy failed.");

        connectInfo = std::make_shared<HksExtAbilityConnectInfo>(want, connect);
        m_providerMap.Insert(providerInfo, connectInfo);
        HKS_LOG_I("OnRegisterProvider Success! providerName: %" LOG_PUBLIC "s", providerName.c_str());
        ret = HKS_SUCCESS;
    } else {
        HKS_LOG_E("OnRegisterProvider failed, providerName: %" LOG_PUBLIC "s, bundleName: %" LOG_PUBLIC "s, "
            "abilityName: %" LOG_PUBLIC "s, already exist", providerName.c_str(), providerInfo.m_bundleName.c_str(),
            providerInfo.m_abilityName.c_str());
        ret = HKS_ERROR_PROVIDER_HAS_REGISTERED;
    }
    return ret;
}

int32_t HksProviderLifeCycleManager::GetExtensionProxy(const ProviderInfo &providerInfo,
    sptr<IHuksAccessExtBase> &proxy)
{
    std::shared_ptr<HksExtAbilityConnectInfo> connectionInfo = nullptr;
    if (!m_providerMap.Find(providerInfo, connectionInfo)) {
        HKS_LOG_E("GetExtensionProxy failed, providerName: %" LOG_PUBLIC "s", providerInfo.m_providerName.c_str());
        return HKS_ERROR_NOT_EXIST;
    }
    HKS_IF_TRUE_LOGE_RETURN(connectionInfo == nullptr, HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
    HKS_IF_TRUE_LOGE_RETURN(connectionInfo->m_connection == nullptr, HKS_ERROR_NULL_POINTER, "m_connection is nullptr")
    proxy = connectionInfo->m_connection->GetExtConnectProxy();
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HapGetAllConnectInfoByProviderName(const std::string &bundleName,
    const std::string &providerName,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &providerInfos)
{
    m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
        std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        if (providerInfo.m_bundleName == bundleName && providerInfo.m_providerName == providerName) {
            providerInfos.emplace_back(providerInfo, connectionInfo);
        }
    });
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetAllProviderInfosByProviderName(const std::string &providerName,
    std::vector<ProviderInfo> &providerInfos)
{
    m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
        std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        if (providerName == "HksInnerNullProviderName") {
            ProviderInfo info = providerInfo;
            info.m_bundleName = providerInfo.m_bundleName;
            info.m_abilityName = providerInfo.m_abilityName;
            info.m_providerName = providerInfo.m_providerName;
            providerInfos.push_back(info);
        } else if (providerInfo.m_providerName == providerName) {
            ProviderInfo info = providerInfo;
            info.m_bundleName = providerInfo.m_bundleName;
            info.m_abilityName = providerInfo.m_abilityName;
            info.m_providerName = providerInfo.m_providerName;
            providerInfos.push_back(info);
        }
    });
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HksHapGetConnectInfos(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &connectionInfos)
{
    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(saMgr, HKS_ERROR_NULL_POINTER, "GetSystemAbilityManager failed")

    sptr<IRemoteObject> remoteObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "GetSystemAbility failed")

    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "iface_cast IBundleMgr failed")

    std::string bundleName;
    auto bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(processInfo.uidInt), bundleName);
    HKS_IF_TRUE_LOGE_RETURN(!bundleRet, HKS_ERROR_BAD_STATE,
        "GetBundleNameForUid failed. external ret: %" LOG_PUBLIC "d", bundleRet)

    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    if (abilityName.first == HKS_SUCCESS) {
        HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() > MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
            "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
        std::string abilityNameStr = std::string(abilityName.second.begin(), abilityName.second.end());
        HKS_LOG_I("HksHapGetConnectInfos abilityName: %" LOG_PUBLIC "s", abilityNameStr.c_str());
        m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
            std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
            if (providerInfo.m_bundleName == bundleName &&
                providerInfo.m_abilityName == abilityNameStr &&
                providerInfo.m_providerName == providerName) {
                connectionInfos.emplace_back(providerInfo, connectionInfo);
            }
        });
        return HKS_SUCCESS;
    }
    return HapGetAllConnectInfoByProviderName(bundleName, providerName, connectionInfos);
}

constexpr int WAIT_TIME_MS = 5;
constexpr int WAIT_ITERATION = 6;
int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet, bool isdeath)
{
    HKS_IF_TRUE_RETURN(!CheckStringParamLenIsOk(providerName, 1, MAX_PROVIDER_NAME_LEN), HKS_ERROR_INVALID_ARGUMENT)
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> connectionInfos;
    std::lock_guard<std::mutex> lock(m_registerMutex);
    this->PrintRegisterProviders();
    int32_t ret = HksHapGetConnectInfos(processInfo, providerName, paramSet, connectionInfos);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Fail to get provider infos. providerName: %" LOG_PUBLIC "s. ret: %" LOG_PUBLIC "d", providerName.c_str(), ret)
    HKS_IF_TRUE_LOGE_RETURN(connectionInfos.empty(), HKS_ERROR_PROVIDER_NOT_FOUND,
        "OnUnRegisterProvider failed, unfound provider connections. providerName: %" LOG_PUBLIC "s",
            providerName.c_str())
    for (auto &connectionInfo : connectionInfos) {
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo.second == nullptr, HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo.second->m_connection == nullptr, HKS_ERROR_NULL_POINTER,
            "m_connection is nullptr")
        auto proxy = connectionInfo.second->m_connection->GetExtConnectProxy();
        if (proxy == nullptr) {
            HKS_LOG_E("OnUnRegisterProvider proxy is nullptr. providerName: %" LOG_PUBLIC "s", providerName.c_str());
            m_providerMap.Erase(connectionInfo.first);
            continue;
        }
        int32_t refCount = proxy->GetSptrRefCount();
        HKS_LOG_I("OnUnRegisterProvider connection want abilityName: %" LOG_PUBLIC "s",
            connectionInfo.second->m_want.GetElement().GetAbilityName().c_str());
        HKS_LOG_I("OnUnRegisterProvider refCount: %" LOG_PUBLIC "d", refCount);
        HKS_IF_TRUE_LOGE_RETURN(refCount > HKS_PROVIDER_CAN_REMOVE_REF_COUNT, HKS_ERROR_PROVIDER_IN_USE,
            "OnUnRegisterProvider failed, refCount is more than 2, maybe in use.")
        
        if (!isdeath) {
            HKS_IF_TRUE_LOGE_RETURN(connectionInfo.second->m_connection == nullptr,
                HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
            connectionInfo.second->m_connection->OnDisconnect(connectionInfo.second->m_connection);
        }
        m_providerMap.Erase(connectionInfo.first);
        auto &stub = connectionInfo.second->m_connection;
        uint8_t waitIteration = WAIT_ITERATION;
        HKS_LOG_I("stub refcount: %" LOG_PUBLIC "d", stub->GetSptrRefCount());
        while ((stub->GetSptrRefCount() > 1) && (waitIteration > 0)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<long long>(WAIT_TIME_MS)));
            HKS_LOG_I("iter stub refcount: %" LOG_PUBLIC "d", stub->GetSptrRefCount());
            waitIteration--;
            HKS_IF_TRUE_LOGE(waitIteration == 0, "waitIteration is 0, but stub refcount is not 1.")
        }
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
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "GetSystemAbility bms failed")

    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "iface_cast IBundleMgr failed")

    auto bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(processInfo.uidInt),
        providerInfo.m_bundleName);
    HKS_IF_TRUE_LOGE_RETURN(!bundleRet, HKS_ERROR_BAD_STATE,
        "GetBundleNameForUid failed. external ret: %" LOG_PUBLIC "d", bundleRet)
    providerInfo.m_providerName = providerName;

    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    HKS_IF_TRUE_LOGE_RETURN(abilityName.first != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "GetParam HKS_EXT_CRYPTO_TAG_ABILITY_NAME failed. ret: %" LOG_PUBLIC "d", abilityName.first)
    HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() > MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
    providerInfo.m_abilityName = std::string(abilityName.second.begin(), abilityName.second.end());
    return HKS_SUCCESS;
}

}