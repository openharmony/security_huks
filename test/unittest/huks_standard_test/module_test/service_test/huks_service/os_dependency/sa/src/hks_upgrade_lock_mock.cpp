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

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL

#include "hks_upgrade_lock.h"
#include "hks_type_enum.h"
#include "hks_test_log.h"

#include <rwlock.h>

namespace OHOS {
namespace Security {
namespace Hks {

static int32_t g_mockHksWaitIfPowerOnUpgradingRet = HKS_SUCCESS;
OHOS::Utils::RWLock g_upgradeOrRequestLock(true);

void SetMockHksWaitIfPowerOnUpgradingRet(int32_t ret)
{
    g_mockHksWaitIfPowerOnUpgradingRet = ret;
}

int32_t HksProcessConditionCreate(void)
{
    return HKS_SUCCESS;
}

int32_t HksWaitIfPowerOnUpgrading(void)
{
    HKS_TEST_LOG_I("mock HksWaitIfPowerOnUpgrading called, ret: %d", g_mockHksWaitIfPowerOnUpgradingRet);
    return g_mockHksWaitIfPowerOnUpgradingRet;
}

void HksUpgradeOnPowerOnDoneNotifyAll(void)
{
    HKS_TEST_LOG_I("mock HksUpgradeOnPowerOnDoneNotifyAll called");
}

}
}
}

static __thread bool g_readLocked = false;

void HksUpgradeOrRequestLockRead(void)
{
    if (g_readLocked) {
        return;
    }
    OHOS::Security::Hks::g_upgradeOrRequestLock.LockRead();
    g_readLocked = true;
}

void HksUpgradeOrRequestUnlockRead(void)
{
    if (!g_readLocked) {
        return;
    }
    OHOS::Security::Hks::g_upgradeOrRequestLock.UnLockRead();
    g_readLocked = false;
}

#endif