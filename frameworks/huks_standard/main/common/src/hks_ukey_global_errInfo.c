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
#include "hks_ukey_global_errInfo.h"
#include "hks_mutex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "securec.h"
#include <pthread.h>
#include <string.h>

struct HksUkeyGlobalInfo g_ukeyGlobalInfo = {0, ""};
static HksMutex *g_ukeyGlobalMutex = NULL;
static pthread_mutex_t g_initMutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_ukeyMutexInitFlag = 0;

static HksMutex* GetUkeyGlobalMutex(void)
{
    if (g_ukeyMutexInitFlag == 0) {
        pthread_mutex_lock(&g_initMutex);
        if (g_ukeyMutexInitFlag == 0) {
            g_ukeyGlobalMutex = HksMutexCreate();
            if (g_ukeyGlobalMutex != NULL) {
                g_ukeyMutexInitFlag = 1;
            } else {
                HKS_LOG_E("Create ukey global mutex failed");
            }
        }
        pthread_mutex_unlock(&g_initMutex);
    }
    return g_ukeyGlobalMutex;
}

void HksSetUkeyGlobalInfo(int32_t errVal, const char *errorDesc)
{
    HksMutex *mutex = GetUkeyGlobalMutex();
    HKS_IF_NULL_LOGE_RETURN_VOID(mutex, "mutex is null")
    
    HksMutexLock(mutex);
    g_ukeyGlobalInfo.errVal = errVal;
    const char *desc = (errorDesc != NULL) ? errorDesc : "";
    uint32_t len = strlen(desc);
    if (len >= HKS_UKEY_ERROR_DESC_MAX_LEN) {
        len = HKS_UKEY_ERROR_DESC_MAX_LEN - 1;
    }
    (void)memcpy_s(g_ukeyGlobalInfo.errorDesc, HKS_UKEY_ERROR_DESC_MAX_LEN, desc, len);
    g_ukeyGlobalInfo.errorDesc[len] = '\0';
    HksMutexUnlock(mutex);
}

int32_t HksGetUkeyGlobalErrVal(void)
{
    HksMutex *mutex = GetUkeyGlobalMutex();
    HKS_IF_NULL_LOGE_RETURN(mutex, 0, "mutex is null")
    
    HksMutexLock(mutex);
    int32_t errVal = g_ukeyGlobalInfo.errVal;
    HksMutexUnlock(mutex);
    return errVal;
}

void HksGetUkeyGlobalErrorDesc(char *buf, uint32_t bufLen)
{
    if (buf == NULL || bufLen == 0) {
        return;
    }
    HksMutex *mutex = GetUkeyGlobalMutex();
    if (mutex == NULL) {
        HKS_LOG_E("HksGetUkeyGlobalErrorDesc: mutex is null");
        buf[0] = '\0';
        return;
    }
    
    HksMutexLock(mutex);
    uint32_t len = strlen(g_ukeyGlobalInfo.errorDesc);
    uint32_t copyLen = (len < bufLen - 1) ? len : bufLen - 1;
    (void)memcpy_s(buf, bufLen, g_ukeyGlobalInfo.errorDesc, copyLen);
    buf[copyLen] = '\0';
    HksMutexUnlock(mutex);
}

void HksClearUkeyGlobalInfo(void)
{
    HksMutex *mutex = GetUkeyGlobalMutex();
    HKS_IF_NULL_LOGE_RETURN_VOID(mutex, "mutex is null")
    
    HksMutexLock(mutex);
    g_ukeyGlobalInfo.errVal = 0;
    g_ukeyGlobalInfo.errorDesc[0] = '\0';
    HksMutexUnlock(mutex);
}