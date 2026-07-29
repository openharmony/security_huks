/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "screen_lock_wrapper.h"
#ifdef THEME_SCREENLOCK_MGR_ENABLE
#include "screenlock_manager.h"
#include "screenlock_common.h"
#endif
#include "hks_log.h"
#include "hks_type.h"
#include <cstdint>


int32_t IsDeviceLocked(int32_t userId, bool *isDeviceLocked)
{
    if (isDeviceLocked == nullptr) {
        LOGE("IsDeviceLocked: isDeviceLocked is nullptr");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    *isDeviceLocked = true;

#ifdef THEME_SCREENLOCK_MGR_ENABLE
    auto screenLockMgr = OHOS::ScreenLock::ScreenLockManager::GetInstance();
    if (screenLockMgr == nullptr) {
        LOGE("ScreenLockManager::GetInstance failed");
        return HKS_ERROR_NOT_SUPPORTED;
    }

    bool locked = false;
    int32_t ret = screenLockMgr->IsDeviceLocked(userId, locked);
    if (ret != OHOS::ScreenLock::E_SCREENLOCK_OK) {
        LOGE("IsDeviceLocked failed, error code: %{public}d", ret);
        return HKS_ERROR_NOT_SUPPORTED;
    }

    *isDeviceLocked = locked;
#endif
    return HKS_SUCCESS;
}

