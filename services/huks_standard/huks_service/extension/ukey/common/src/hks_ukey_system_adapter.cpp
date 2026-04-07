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

#include "hks_ukey_system_adapter.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_template.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"

namespace OHOS::Security::Huks {

int32_t HksGetFrontUserId(int32_t &outId)
{
    std::vector<int> ids{};
    int ret = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    HKS_IF_TRUE_LOGE_RETURN(ret != OHOS::ERR_OK || ids.empty(), HKS_FAILURE,
        "QueryActiveOsAccountIds Failed!! ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("QueryActiveOsAccountIds success: FrontUserId= %" LOG_PUBLIC "d", ids[0]);
    outId = ids[0];
    return HKS_SUCCESS;
}

int32_t HksGetBundleNameFromUid(uint32_t uid, std::string &bundleName)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> saMgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(saMgr, HKS_ERROR_NULL_POINTER, "GetBundleNameFromUid GetSystemAbilityManager failed");

    OHOS::sptr<OHOS::IRemoteObject> remoteObj =
        saMgr->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    HKS_IF_NULL_LOGE_RETURN(remoteObj, HKS_ERROR_NULL_POINTER, "GetBundleNameFromUid GetSystemAbility bms failed");

    auto bundleMgrProxy = OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObj);
    HKS_IF_NULL_LOGE_RETURN(bundleMgrProxy, HKS_ERROR_NULL_POINTER,
        "GetBundleNameFromUid iface_cast IBundleMgr failed");

    bool bundleRet = bundleMgrProxy->GetBundleNameForUid(static_cast<int32_t>(uid), bundleName);
    HKS_IF_NOT_TRUE_LOGE_RETURN(bundleRet, HKS_ERROR_BAD_STATE,
        "GetBundleNameFromUid GetBundleNameForUid failed for uid: %{public}u", uid);

    return HKS_SUCCESS;
}

}
