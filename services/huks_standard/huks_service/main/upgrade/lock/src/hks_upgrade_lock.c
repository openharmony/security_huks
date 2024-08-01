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

HksMutex *g_upgradeMutex = NULL;
HksMutex *g_upgradingMutex = NULL;
volatile bool g_upgrading = false;

HksCondition *g_processCondition = NULL;

int32_t HksProcessConditionCreate(void)
{
    g_processCondition = HksConditionCreate();
    if (g_processCondition == NULL) {
        HKS_LOG_E("create process condition failed.");
        return HKS_ERROR_BAD_STATE;
    }
    return HKS_SUCCESS;
}

static int32_t HksProcessConditionWait(void)
{
    return HksConditionWait(g_processCondition);
}

static int32_t HksProcessConditionNotifyAll(void)
{
    return HksConditionNotifyAll(g_processCondition);
}

int32_t HksWaitIfUpgrading(void)
{
    if (HksMutexLock(g_upgradingMutex) != 0) {
        HKS_LOG_E("lock g_upgrading failed.");
    }
    if (g_upgrading) {
        if (HksMutexUnlock(g_upgradingMutex) != 0) {
            HKS_LOG_E("unlock g_upgrading failed.");
        }
        HKS_LOG_I("upgrading, wait...");
        return HksProcessConditionWait();
    }
    if (HksMutexUnlock(g_upgradingMutex) != 0) {
        HKS_LOG_E("unlock g_upgrading failed.");
    }
    return HKS_SUCCESS;
}

int32_t HksUpgradeLockCreate(void)
{
    g_upgradeMutex = HksMutexCreate();
    if (g_upgradeMutex == NULL) {
        HKS_LOG_E("create upgrade mutex failed.");
        return HKS_ERROR_BAD_STATE;
    }
    g_upgradingMutex = HksMutexCreate();
    if (g_upgradingMutex == NULL) {
        HKS_LOG_E("create g_upgrading mutex failed.");
    }
    return HKS_SUCCESS;
}

void HksUpgradeLock(void)
{
    HKS_LOG_I("get upgrade lock");
    if (HksMutexLock(g_upgradeMutex) != 0) {
        HKS_LOG_E("lock upgrade failed.");
        return;
    }
    g_upgrading = true;
}

void HksUpgradeUnlock(void)
{
    HKS_LOG_I("release upgrade lock");
    if (HksMutexUnlock(g_upgradeMutex) != 0) {
        HKS_LOG_E("unlock upgrade failed.");
        // if fail, continue so the huks can work properly
    }
    if (HksMutexLock(g_upgradingMutex) != 0) {
        HKS_LOG_E("lock g_upgrading failed.");
    }
    g_upgrading = false;
    if (HksMutexUnlock(g_upgradingMutex) != 0) {
        HKS_LOG_E("unlock g_upgrading failed.");
    }
    HksProcessConditionNotifyAll();
}
