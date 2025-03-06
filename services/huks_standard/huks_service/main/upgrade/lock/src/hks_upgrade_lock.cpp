/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hks_upgrade_lock.h"

#include "hks_condition.h"
#include "hks_mutex.h"
#include "hks_template.h"
#include "hks_type_enum.h"

#include <rwlock.h>
#include <atomic>

static __thread bool g_readLocked = false;

namespace OHOS {
namespace Security {
namespace Hks {
static HksCondition *g_powerOnUpgradeCondition = NULL;
OHOS::Utils::RWLock g_upgradeOrRequestLock(true);

int32_t HksProcessConditionCreate(void)
{
    g_powerOnUpgradeCondition = HksConditionCreate();
    HKS_IF_NULL_LOGE_RETURN(g_powerOnUpgradeCondition, HKS_ERROR_BAD_STATE, "create process condition failed.")
    return HKS_SUCCESS;
}

int32_t HksWaitIfPowerOnUpgrading(void)
{
    int32_t ret = HksConditionWait(g_powerOnUpgradeCondition);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE,
        "HksWaitIfPowerOnUpgrading HksConditionWait fail %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

void HksUpgradeOnPowerOnDoneNotifyAll(void)
{
    HKS_LOG_I("HksUpgradeOnPowerOnDoneNotifyAll HksConditionNotifyAll");
    int32_t ret = HksConditionNotifyAll(g_powerOnUpgradeCondition);
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(ret,
        "HksUpgradeOnPowerOnDoneNotifyAll HksConditionNotifyAll fail %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("HksUpgradeOnPowerOnDoneNotifyAll HksConditionNotifyAll ok!");
}
}
}
}

void HksUpgradeOrRequestLockRead(void)
{
    HKS_IF_TRUE_RETURN_VOID(g_readLocked)
    OHOS::Security::Hks::g_upgradeOrRequestLock.LockRead();
    g_readLocked = true;
}

void HksUpgradeOrRequestUnlockRead(void)
{
    HKS_IF_NOT_TRUE_RETURN_VOID(g_readLocked)
    OHOS::Security::Hks::g_upgradeOrRequestLock.UnLockRead();
    g_readLocked = false;
}
