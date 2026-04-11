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
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_info.h"
#include "hks_ukey_system_adapter.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_plugin_def.h"
#include "hks_template.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "refbase.h"
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <chrono>
#include <thread>
namespace OHOS::Security::Huks {

bool ProviderIndexKey::operator==(const ProviderIndexKey &other) const
{
    return providerInfo == other.providerInfo && index == other.index;
}

bool ProviderIndexKey::operator<(const ProviderIndexKey &other) const
{
    if (providerInfo < other.providerInfo) {
        return true;
    }
    if (other.providerInfo < providerInfo) {
        return false;
    }
    return index < other.index;
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
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(HksProcessInfo)> callback)
{
    HKS_LOG_I("OnRegisterProvider providerName: %" LOG_PUBLIC "s", providerName.c_str());
    HKS_IF_TRUE_RETURN(!CheckStringParamLenIsOk(providerName, 1, MAX_PROVIDER_NAME_LEN), HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_LOGE_RETURN(m_providerMap.Size() >= HKS_MAX_PROVIDER_NUM,
        HKS_ERROR_UKY_PROVIDER_MGR_REGESTER_REACH_MAX_NUM, "OnRegisterProvider failed, providerNum is too much.")
    ProviderInfo providerInfo{};
    int32_t ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Fail to get provider info. providerName: %" LOG_PUBLIC "s. ret: %" LOG_PUBLIC "d", providerName.c_str(), ret)
    HKS_LOG_I("bundleName: %" LOG_PUBLIC "s, (abilityName: %" LOG_PUBLIC "s",
        providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str());
    std::shared_ptr<HksExtAbilityConnectInfo> connectInfo{nullptr};

    {
        std::lock_guard<std::mutex> lock(m_registerMutex);
        this->PrintRegisterProviders();
        HKS_IF_TRUE_LOGE_RETURN(m_providerMap.Find(providerInfo, connectInfo),
            HKS_ERROR_PROVIDER_HAS_REGISTERED, "OnRegisterProvider failed, providerName: %" LOG_PUBLIC "s,"
            "bundleName: %" LOG_PUBLIC "s, abilityName: %" LOG_PUBLIC "s, already exist", providerName.c_str(),
            providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str())
        AAFwk::Want want{};
        want.SetElementName(providerInfo.m_bundleName, providerInfo.m_abilityName);
        sptr<ExtensionConnection> connect(new (std::nothrow) ExtensionConnection(processInfo));
        HKS_IF_TRUE_LOGE_RETURN(connect == nullptr, HKS_ERROR_NULL_POINTER, "new ExtensionConnection failed");
        connect->callBackFromPlugin(callback);
        if (!connect->IsConnected()) {
            HKS_LOG_I("First time connect to Extension Ability. "
                "m_bundleName: %" LOG_PUBLIC "s, m_abilityName: %" LOG_PUBLIC "s",
                providerInfo.m_bundleName.c_str(), providerInfo.m_abilityName.c_str());
            ret = connect->OnConnection(want, connect, processInfo.userIdInt);
            HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "Connect extAbility failed. ret: %" LOG_PUBLIC "d", ret)
        }

        auto proxy = connect->GetExtConnectProxy();
        HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NULL_POINTER, "connected, but getExtConnectProxy failed.");

        connectInfo = std::make_shared<HksExtAbilityConnectInfo>(want, connect);
        m_providerMap.Insert(providerInfo, connectInfo);
        HKS_LOG_I("OnRegisterProvider Success! providerName: %" LOG_PUBLIC "s", providerName.c_str());
    }
    
    auto abilityInfoTag = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_INFO>();
    HKS_IF_TRUE_LOGI_RETURN(abilityInfoTag.first != HKS_SUCCESS, ret, "there is no UiAbility")

    std::string jsonStr = std::string(abilityInfoTag.second.begin(), abilityInfoTag.second.end());
    ret = RegisterUiAbility(processInfo, providerName, paramSet, jsonStr);

    return ret;
}

int32_t HksProviderLifeCycleManager::OnQueryAbility(const HksProcessInfo &processInfo,
    std::string &resourceId, CppAbilityInfo &abilityInfo)
{
    ProviderInfo providerInfo{};
    std::string index{};
    GetProviderInfoAndIndex(resourceId, providerInfo, index);
    providerInfo.m_userid = processInfo.userIdInt;
    ProviderIndexKey indexKey(providerInfo, index);

    std::lock_guard<std::mutex> indexLock(m_providerIndexMutex);
    std::string abilityName{};
    auto it = m_providerIndexMap.Find(indexKey, abilityName);
    if (!it) {
        indexKey.index = "";
        auto res = m_providerIndexMap.Find(indexKey, abilityName);
        HKS_IF_NOT_TRUE_LOGE_RETURN(res, HKS_ERROR_NOT_EXIST, "Ui Ability not found");
    }
    
    abilityInfo.abilityName = abilityName;
    abilityInfo.bundleName = providerInfo.m_bundleName;
    resourceId = index;
    return HKS_SUCCESS;
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
    HKS_IF_TRUE_LOGE_RETURN(proxy == nullptr, HKS_ERROR_NULL_POINTER, "GetExtConnectProxy failed. proxy is nullptr")
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HapGetAllConnectInfoByProviderName(const std::string &bundleName,
    const std::string &providerName, const int32_t userid,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &providerInfos)
{
    m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
        std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        if (providerInfo.m_bundleName == bundleName && providerInfo.m_providerName == providerName &&
            providerInfo.m_userid == userid) {
            providerInfos.emplace_back(providerInfo, connectionInfo);
        }
    });
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetAllProviderInfosByProviderName(const std::string &providerName,
    const int32_t &userid, std::vector<ProviderInfo> &providerInfos)
{
    HKS_LOG_I("GetAllProviderInfosByProviderName providerName: %" LOG_PUBLIC "s", providerName.c_str());
    int32_t frontUserId;
    int32_t ret = HksGetFrontUserId(frontUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get front user id failed")
    ret = HKS_ERROR_INVALID_ARGUMENT;
    m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
        std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
        if (providerInfo.m_userid == frontUserId) {
            if (providerName == "HksInnerNullProviderName") {
                ProviderInfo info = providerInfo;
                providerInfos.push_back(info);
                ret = HKS_SUCCESS;
            } else if (providerInfo.m_providerName == providerName) {
                ProviderInfo info = providerInfo;
                providerInfos.push_back(info);
                ret = HKS_SUCCESS;
            }
        }
    });
    return ret;
}

int32_t HksProviderLifeCycleManager::HksHapGetConnectInfos(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &connectionInfos)
{
    std::string bundleName;
    int32_t ret = HksGetBundleNameFromUid(processInfo.uidInt, bundleName);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "HksGetBundleNameFromUid failed. ret: %" LOG_PUBLIC "d", ret)

    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    if (abilityName.first == HKS_SUCCESS) {
        HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() >= MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
            "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
        std::string abilityNameStr = std::string(abilityName.second.begin(), abilityName.second.end());
        HKS_LOG_I("HksHapGetConnectInfos abilityName: %" LOG_PUBLIC "s", abilityNameStr.c_str());
        m_providerMap.Iterate([&](const ProviderInfo &providerInfo,
            std::shared_ptr<HksExtAbilityConnectInfo> &connectionInfo) {
            if (providerInfo.m_bundleName == bundleName &&
                providerInfo.m_abilityName == abilityNameStr &&
                providerInfo.m_providerName == providerName &&
                providerInfo.m_userid == processInfo.userIdInt) {
                connectionInfos.emplace_back(providerInfo, connectionInfo);
            }
        });
        return HKS_SUCCESS;
    }
    return HapGetAllConnectInfoByProviderName(bundleName, providerName, processInfo.userIdInt, connectionInfos);
}

int32_t HksProviderLifeCycleManager::UnregisterAllUiExtensionsByProviderInfo(
    const ProviderInfo &providerInfo)
{
    HKS_LOG_I("UnregisterAllUiExtensionsByProviderInfo providerName: %" LOG_PUBLIC "s, abilityName: %" LOG_PUBLIC "s",
        providerInfo.m_providerName.c_str(), providerInfo.m_abilityName.c_str());

    ProviderInfo searchProviderInfo = providerInfo;

    std::vector<ProviderIndexKey> keysToDelete{};
    {
        std::lock_guard<std::mutex> indexLock(m_providerIndexMutex);
        m_providerIndexMap.Iterate([&](const ProviderIndexKey &key, const std::string &abilityName) {
            if (key.providerInfo == searchProviderInfo) {
                HKS_LOG_I("Found matching UI Extension: abilityName: %" LOG_PUBLIC "s, index: %" LOG_PUBLIC "s",
                    abilityName.c_str(), key.index.c_str());
                keysToDelete.push_back(key);
            }
        });

        for (const auto &key : keysToDelete) {
            HKS_LOG_I("Deleting UI Extension: index: %" LOG_PUBLIC "s", key.index.c_str());
            m_providerIndexMap.Erase(key);
        }
    }
    
    HKS_LOG_I("UnregisterAllUiExtensionsByProviderInfo Success! providerName: %" LOG_PUBLIC "s,"
        "deleted count: %" LOG_PUBLIC "zu", providerInfo.m_providerName.c_str(), keysToDelete.size());
    return HKS_SUCCESS;
}

constexpr int WAIT_TIME_MS = 5;
constexpr int WAIT_ITERATION = 6;
int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount)
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
    int32_t deletecount = 0;
    for (auto &connectionInfo : connectionInfos) {
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo.second == nullptr, HKS_ERROR_NULL_POINTER, "connectionInfo is nullptr")
        HKS_IF_TRUE_LOGE_RETURN(connectionInfo.second->m_connection == nullptr, HKS_ERROR_NULL_POINTER,
            "m_connection is nullptr")
        auto proxy = connectionInfo.second->m_connection->GetExtConnectProxy();
        if (proxy == nullptr) {
            HKS_LOG_E("OnUnRegisterProvider proxy is nullptr. providerName: %" LOG_PUBLIC "s", providerName.c_str());
            m_providerMap.Erase(connectionInfo.first);
            UnregisterAllUiExtensionsByProviderInfo(connectionInfo.first);
            deletecount++;
            continue;
        }
        int32_t refCount = proxy->GetSptrRefCount();
        HKS_LOG_I("OnUnRegisterProvider connection want abilityName: %" LOG_PUBLIC "s",
            connectionInfo.second->m_want.GetElement().GetAbilityName().c_str());
        HKS_LOG_I("OnUnRegisterProvider refCount: %" LOG_PUBLIC "d", refCount);
        HKS_IF_TRUE_LOGE_RETURN(refCount > HKS_PROVIDER_CAN_REMOVE_REF_COUNT, HKS_ERROR_PROVIDER_IN_USE,
            "OnUnRegisterProvider failed, refCount is more than 2, maybe in use.")
        HKS_IF_NOT_TRUE_EXCU(isdeath,
            connectionInfo.second->m_connection->OnDisconnect(connectionInfo.second->m_connection));
        m_providerMap.Erase(connectionInfo.first);
        UnregisterAllUiExtensionsByProviderInfo(connectionInfo.first);
        deletecount++;
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
    deleteCount = deletecount;
    HKS_LOG_I("OnUnRegisterProvider Success! providerName: %" LOG_PUBLIC "s", providerName.c_str());
    return HKS_SUCCESS;
}

int32_t HksGetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, ProviderInfo &providerInfo)
{
    int32_t ret = HksGetBundleNameFromUid(processInfo.uidInt, providerInfo.m_bundleName);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "HksGetBundleNameFromUid failed. ret: %" LOG_PUBLIC "d", ret)

    providerInfo.m_providerName = providerName;
    auto abilityName = paramSet.GetParam<HKS_EXT_CRYPTO_TAG_ABILITY_NAME>();
    HKS_IF_TRUE_LOGE_RETURN(abilityName.first != HKS_SUCCESS, HKS_ERROR_ABILITY_NAME_MISSING,
        "GetParam HKS_EXT_CRYPTO_TAG_ABILITY_NAME failed. ret: %" LOG_PUBLIC "d", abilityName.first)
    HKS_IF_TRUE_LOGE_RETURN(abilityName.second.size() >= MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "the abilityName is too long. size: %" LOG_PUBLIC "zu", abilityName.second.size())
    providerInfo.m_abilityName = std::string(abilityName.second.begin(), abilityName.second.end());
    providerInfo.m_userid = processInfo.userIdInt;
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::CheckProviderIndexDuplicate(const ProviderIndexKey &key)
{
    std::string abilityName{};
    std::lock_guard<std::mutex> lock(m_providerIndexMutex);
    if (m_providerIndexMap.Find(key, abilityName)) {
        HKS_LOG_E("ProviderIndexKey already exists. providerName: %" LOG_PUBLIC "s, "
            "abilityName: %" LOG_PUBLIC "s, index: %" LOG_PUBLIC "s",
            key.providerInfo.m_providerName.c_str(), key.providerInfo.m_abilityName.c_str(), key.index.c_str());
        return HKS_ERROR_PROVIDER_HAS_REGISTERED;
    }
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::RegisterUiAbility(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string jsonStr)
{
    int32_t ret = 0;
    HKS_LOG_I("New flow with HKS_EXT_CRYPTO_TAG_ABILITY_INFO");
    std::vector<AbilityInfo> abilityInfoArray{};
    do {
        ret = ParseAbilityInfoArrayFromJson(jsonStr, abilityInfoArray);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "ParseAbilityInfoArrayFromJson failed. ret: %" LOG_PUBLIC "d", ret)
        ret = RegisterProviderWithIndexArray(processInfo, providerName, paramSet, abilityInfoArray);
        HKS_IF_TRUE_LOGI_RETURN(ret == HKS_SUCCESS, ret,
            "RegisterProviderWithIndexArray Success! providerName: %" LOG_PUBLIC "s", providerName.c_str())
    } while (0);
    int32_t deletCount = 0;
    (void)OnUnRegisterProvider(processInfo, providerName, paramSet, false, deletCount);
    HKS_LOG_E("OnRegisterProvider fail");
    return ret;
}

int32_t HksProviderLifeCycleManager::RegisterProviderWithIndexArray(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, const std::vector<AbilityInfo> &abilityInfoArray)
{
    HKS_LOG_I("RegisterProviderWithIndexArray providerName: %" LOG_PUBLIC "s, ability count: %" LOG_PUBLIC "zu",
        providerName.c_str(), abilityInfoArray.size());
    
    for (const auto &abilityInfo : abilityInfoArray) {
        int32_t ret = RegisterSingleAbilityWithIndex(processInfo, providerName, paramSet, abilityInfo);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "regitst ui: %" LOG_PUBLIC "s fail", abilityInfo.abilityName.c_str())
    }
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::RegisterSingleAbilityWithIndex(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, const AbilityInfo &abilityInfo)
{
    HKS_LOG_I("RegisterSingleAbilityWithIndex providerName: %" LOG_PUBLIC "s, uiAbilityName: %" LOG_PUBLIC "s,"
        "index: %" LOG_PUBLIC "s", providerName.c_str(), abilityInfo.abilityName.c_str(), abilityInfo.index.c_str());
    
    ProviderInfo providerInfo{};
    int32_t ret = HksGetProviderInfo(processInfo, providerName, paramSet, providerInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "HksGetProviderInfo failed. ret: %" LOG_PUBLIC "d", ret)
    
    HKS_IF_TRUE_LOGE_RETURN(abilityInfo.abilityName.size() >= MAX_ABILITY_NAME_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "the uiAbilityName is too long. size: %" LOG_PUBLIC "zu", abilityInfo.abilityName.size())
    
    ProviderIndexKey indexKey{providerInfo, abilityInfo.index};
    ret = CheckProviderIndexDuplicate(indexKey);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CheckProviderIndexDuplicate failed. ret: %" LOG_PUBLIC "d", ret)
    
    {
        std::lock_guard<std::mutex> indexLock(m_providerIndexMutex);
        m_providerIndexMap.Insert(indexKey, abilityInfo.abilityName);
    }
    
    HKS_LOG_I("RegisterSingleAbilityWithIndex Success! providerName: %" LOG_PUBLIC "s, index: %" LOG_PUBLIC "s",
        providerName.c_str(), abilityInfo.index.c_str());
    return HKS_SUCCESS;
}
}