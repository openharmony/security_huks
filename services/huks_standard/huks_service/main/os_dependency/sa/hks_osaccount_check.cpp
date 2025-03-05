/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef L2_STANDARD
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#include "hks_upgrade.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_osaccount_check.h"

#include <atomic>

#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART

namespace {
static volatile std::atomic_bool g_isCeUpgradeSucc = false;

static bool HksIsOsAccountVerified(const int32_t userId)
{
    bool isVerified = false;
#ifdef HAS_OS_ACCOUNT_PART
    HKS_LOG_D("enter HksIsOsAccountVerified");
    OHOS::AccountSA::OsAccountManager::IsOsAccountVerified(userId, isVerified);
    HKS_IF_NOT_TRUE_LOGE(isVerified, "os account verify failed, userid is : %" LOG_PUBLIC "d", userId)
#else
    HKS_LOG_E("os account not support");
#endif
    return isVerified;
}
}

extern "C" void HksTransferFileIfNeed(const uint32_t storageLevel, const int32_t storeUserId)
{
    bool flag = false;
    HKS_IF_NOT_TRUE_RETURN_VOID(std::atomic_compare_exchange_strong(&g_isCeUpgradeSucc, &flag, true));
    HKS_LOG_I("never HksTransferFileIfNeed before, first time upgrade ce!");
    HKS_IF_NOT_TRUE_RETURN_VOID(storageLevel == HKS_AUTH_STORAGE_LEVEL_CE && HksIsOsAccountVerified(storeUserId))
    OHOS::Security::Hks::HksUpgradeOnUserUnlock(storeUserId);
}

#endif // HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#endif // L2_STANDARD