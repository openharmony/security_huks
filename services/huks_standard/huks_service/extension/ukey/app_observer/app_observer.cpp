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
 
#include "app_observer.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_remote_handle_manager.h"
#include "hks_ukey_session_manager.h"
#include "hks_template.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "app_mgr_interface.h"
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace Security {
namespace Huks {
#define DELAY_10MS_IN_US (10 * 1000)

HksAppObserver::HksAppObserver(const std::string &bundleName)
    : targetBundleName_(bundleName)
{
}

void HksAppObserver::AddProcessContext(const HksProcessInfo &processInfo, const CppParamSet &paramSet)
{
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t uid = processInfo.uidInt;
    auto it = uidToContextMap_.find(uid);
    if (it != uidToContextMap_.end()) {
        it->second = HksProcessContext(processInfo, paramSet);
    } else {
        uidToContextMap_.emplace(uid, HksProcessContext(processInfo, paramSet));
    }
}

CppParamSet HksAppObserver::BuildParamSet(const HksProcessContext &context)
{
    if (context.abilityName.empty()) {
        return CppParamSet(std::vector<HksParam>{});
    }

    std::vector<uint8_t> abilityNameVec(context.abilityName.begin(), context.abilityName.end());
    HksParam param = {
        .tag = HKS_EXT_CRYPTO_TAG_ABILITY_NAME,
        .blob = {
            .size = static_cast<uint32_t>(abilityNameVec.size()),
            .data = abilityNameVec.data()
        }
    };
    return CppParamSet({param});
}

void HksAppObserver::OnAppStopped(const AppExecFwk::AppStateData &appStateData)
{
    HKS_LOG_I("OnAppStopped bundleName = %" LOG_PUBLIC "s, uid = %" LOG_PUBLIC "d, pid = %" LOG_PUBLIC "d",
        appStateData.bundleName.c_str(), appStateData.uid, appStateData.pid);
    if (appStateData.bundleName != targetBundleName_) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    uint32_t diedUid = static_cast<uint32_t>(appStateData.uid);
    auto it = uidToContextMap_.find(diedUid);
    if (it == uidToContextMap_.end()) {
        HKS_LOG_I("OnAppStopped No context found for died uid=%{public}u, skip", diedUid);
        return;
    }

    const HksProcessContext &context = it->second;

    HksProcessInfo processInfo = {};
    processInfo.uidInt = context.uidInt;

    CppParamSet paramSet = BuildParamSet(context);

    auto sessionMgr = HksSessionManager::GetInstanceWrapper();
    HKS_IF_NULL_LOGE_RETURN_VOID(sessionMgr, "sessionMgr is null");
    auto retBool = sessionMgr->HksClearHandle(processInfo, paramSet);
    HKS_IF_NOT_TRUE_LOGI(retBool, "OnAppStopped HksClearHandle failed for uid=%{public}u", diedUid);

    auto handleMgr = HksRemoteHandleManager::GetInstanceWrapper();
    HKS_IF_NULL_LOGE_RETURN_VOID(handleMgr, "handleMgr is null");
    handleMgr->ClearAuthState(processInfo);
    handleMgr->ClearMapByUid(processInfo.uidInt);
    uidToContextMap_.erase(it);
    if (uidToContextMap_.empty()) {
        HksAppObserverManager::GetInstance().CleanupTriggeredObserver(targetBundleName_);
    }
}

HksAppObserverManager& HksAppObserverManager::GetInstance()
{
    static HksAppObserverManager instance;
    return instance;
}

int32_t HksAppObserverManager::GetBundleNameByUid(uint32_t uid, std::string &bundleName)
{
    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(saMgr, HKS_ERROR_NULL_POINTER, "GetBundleNameByUid GetSystemAbilityManager failed");

    sptr<IRemoteObject> remoteObj = saMgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "[GetBundleNameByUid] GetSystemAbility bms failed");

    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER, "GetBundleNameByUid iface_cast IBundleMgr failed");

    bool bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(uid), bundleName);
    HKS_IF_NOT_TRUE_LOGE_RETURN(bundleRet, HKS_FAILURE,
        "GetBundleNameByUid GetBundleNameForUid failed for uid: %{public}u", uid);

    return HKS_SUCCESS;
}

int32_t HksAppObserverManager::RegisterObserver(const HksProcessInfo &processInfo, const CppParamSet &paramSet)
{
    std::string bundleName{};
    int32_t ret = GetBundleNameByUid(processInfo.uidInt, bundleName);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "RegisterObserver Failed to get bundle name for uid: %{public}u", processInfo.uidInt);

    HKS_IF_TRUE_LOGE_RETURN(bundleName.empty(), HKS_ERROR_INVALID_ARGUMENT,
        "RegisterObserver Bundle name is empty for uid: %{public}u", processInfo.uidInt);

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = observers_.find(bundleName);
    if (it != observers_.end()) {
        HKS_IF_NULL_LOGE_RETURN(it->second, HKS_ERROR_NULL_POINTER,
            "Observer for bundleName %" LOG_PUBLIC "s is nullptr", bundleName.c_str())
        it->second->AddProcessContext(processInfo, paramSet);
        return HKS_SUCCESS;
    }

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(samgr, HKS_ERROR_NULL_POINTER, "RegisterObserver Get SystemAbilityManager failed");

    auto remote = samgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    HKS_IF_NULL_LOGE_RETURN(remote, HKS_ERROR_NULL_POINTER, "RegisterObserver Get APP_MGR_SERVICE failed");

    auto appMgr = iface_cast<AppExecFwk::IAppMgr>(remote);
    HKS_IF_NULL_LOGE_RETURN(appMgr, HKS_ERROR_NULL_POINTER, "RegisterObserver Cast to IAppMgr failed");

    sptr<HksAppObserver> observer = new (std::nothrow) HksAppObserver(bundleName);
    HKS_IF_NULL_LOGE_RETURN(observer, HKS_ERROR_MALLOC_FAIL, "RegisterObserver Create HksAppObserver failed");

    observer->AddProcessContext(processInfo, paramSet);
    int32_t regRet = appMgr->RegisterApplicationStateObserver(observer);
    HKS_IF_TRUE_LOGE_RETURN(regRet != 0, HKS_FAILURE,
        "RegisterObserver RegisterApplicationStateObserver failed, ret=%{public}d", regRet);

    observers_[bundleName] = observer;
    HKS_LOG_I("RegisterObserver: New observer registered for bundle: %{public}s", bundleName.c_str());

    return HKS_SUCCESS;
}

int32_t HksAppObserverManager::UnregisterAllObservers()
{
    std::lock_guard<std::mutex> lock(mutex_);

    HKS_IF_TRUE_LOGI_RETURN(observers_.empty(), HKS_SUCCESS, "UnregisterAllObservers: No observers to unregister");

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(samgr, HKS_ERROR_NULL_POINTER, "UnregisterAllObservers: Get SystemAbilityManager failed");

    auto remote = samgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    HKS_IF_NULL_LOGE_RETURN(remote, HKS_ERROR_NULL_POINTER, "UnregisterAllObservers: Get APP_MGR_SERVICE failed");

    auto appMgr = iface_cast<AppExecFwk::IAppMgr>(remote);
    HKS_IF_NULL_LOGE_RETURN(appMgr, HKS_ERROR_NULL_POINTER, "UnregisterAllObservers: Cast to IAppMgr failed");

    int32_t finalRet = HKS_SUCCESS;
    int32_t totalCount = static_cast<int32_t>(observers_.size());
    int32_t failedCount = 0;

    for (const auto& [bundleName, observer] : observers_) {
        int32_t ret = appMgr->UnregisterApplicationStateObserver(observer);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("UnregisterAllObservers: Failed for bundle %{public}s, ret=%{public}d", bundleName.c_str(), ret);
            finalRet = HKS_ERROR_INTERNAL_ERROR;
            failedCount++;
        } else {
            HKS_LOG_I("UnregisterAllObservers: Successfully unregistered observer for bundle: %{public}s",
                bundleName.c_str());
        }
    }
    observers_.clear();

    int32_t successCount = totalCount - failedCount;
    HKS_LOG_I("UnregisterAllObservers: Completed, total=%{public}d, success=%{public}d,"
        "failed=%{public}d, finalRet=%{public}d", totalCount, successCount, failedCount, finalRet);
    usleep(DELAY_10MS_IN_US);
    return finalRet;
}

void HksAppObserverManager::CleanupTriggeredObserver(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = observers_.find(bundleName);
    HKS_IF_TRUE_LOGI_RETURN_VOID(it == observers_.end(),
        "Observer not found for bundle: %{public}s", bundleName.c_str());

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN_VOID(samgr, "Get SystemAbilityManager failed");

    auto remote = samgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    HKS_IF_NULL_LOGE_RETURN_VOID(remote, "Get APP_MGR_SERVICE failed");

    auto appMgr = iface_cast<AppExecFwk::IAppMgr>(remote);
    HKS_IF_NULL_LOGE_RETURN_VOID(appMgr, "Cast to IAppMgr failed");

    int32_t ret = appMgr->UnregisterApplicationStateObserver(it->second);
    HKS_IF_NOT_SUCC_LOGE(ret, "UnregisterApplicationStateObserver failed, ret=%{public}d", ret);

    observers_.erase(it);

    HKS_LOG_I("CleanupTriggeredObserver: Observer removed for bundle: %{public}s", bundleName.c_str());
}

} // namespace Huks
} // namespace Security
} // namespace OHOS