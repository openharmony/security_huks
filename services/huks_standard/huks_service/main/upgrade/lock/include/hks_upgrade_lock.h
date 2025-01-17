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

#ifndef HKS_UPGRADE_LOCK_H
#define HKS_UPGRADE_LOCK_H

#ifdef __cplusplus
#include <rwlock.h>

namespace OHOS {
namespace Security {
namespace Hks {

// OnStart upgrade <==> write, first time using ce level key upgrade <==> write
// OnRemoteRequest <==> read, OnReceiveEvent <==> read
extern OHOS::Utils::RWLock g_upgradeOrRequestLock;

int32_t HksProcessConditionCreate(void);

int32_t HksWaitIfPowerOnUpgrading(void);

void HksUpgradeOnPowerOnDoneNotifyAll(void);

}
}
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

void HksUpgradeOrRequestLockRead(void);

void HksUpgradeOrRequestUnlockRead(void);

#ifdef __cplusplus
}
#endif

#endif // HKS_UPGRADE_LOCK_H
