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

#include "hks_upgrade.h"

#include "hks_template.h"
#include "hks_type_enum.h"
#include "hks_upgrade_lock.h"
#include "rwlock.h"

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#include "hks_file_transfer.h"
#endif

namespace OHOS {
namespace Security {
namespace Hks {
void HksUpgradeOnPowerOn(void)
{
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    HKS_IF_NOT_SUCC_LOGE(HksUpgradeFileTransferOnPowerOn(), "HksUpgradeFileTransfer on power on failed!")
#endif
}

void HksUpgradeOnUserUnlock(uint32_t userId)
{
    HKS_LOG_I("enter HksUpgradeOnUserUnlock.");
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    HksUpgradeOrRequestUnlockRead();

    // Since current thread have owned read lock, the power on upgrade have ended at earlier time,
    // waiting for notify is not necessary.
    {
        HKS_LOG_I("acquiring for write lock...");
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> writeGuard(g_upgradeOrRequestLock);
        int ret = HksUpgradeFileTransferOnUserUnlock(userId);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksUpgradeFileTransferOnUserUnlock failed! %" LOG_PUBLIC "d", ret);
        } else {
            HKS_LOG_I("HksUpgradeFileTransferOnUserUnlock ok!");
        }
    }

    HksUpgradeOrRequestLockRead();
#endif
    HKS_LOG_I("leave HksUpgradeOnUserUnlock.");
}
}
}
}
