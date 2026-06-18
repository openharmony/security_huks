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
    
    const char *desc = (errorDesc != NULL) ? errorDesc : "";
    uint32_t descLen = strlen(desc);

    g_ukeyGlobalInfo.errVal = errVal;
    descLen = (descLen > HKS_UKEY_ERROR_DESC_MAX_LEN) ? HKS_UKEY_ERROR_DESC_MAX_LEN : descLen;

    HKS_IF_TRUE_EXCU(memcpy_s(g_ukeyGlobalInfo.errorDesc, HKS_UKEY_ERROR_BUFFER_SIZE,
        HKS_UKEY_ERROR_PREFIX, HKS_UKEY_ERROR_PREFIX_LEN) != EOK, HKS_LOG_E("copy UkeyErrorPrefix failed!"));

    HKS_IF_TRUE_EXCU(memcpy_s(g_ukeyGlobalInfo.errorDesc + HKS_UKEY_ERROR_PREFIX_LEN,
        HKS_UKEY_ERROR_BUFFER_SIZE - HKS_UKEY_ERROR_PREFIX_LEN, desc, descLen) != EOK,
        HKS_LOG_E("copy error description failed!"));
    g_ukeyGlobalInfo.errorDesc[HKS_UKEY_ERROR_PREFIX_LEN + descLen] = '\0';
    
    HksMutexUnlock(mutex);
}

void HksGetUkeyGlobalInfo(int32_t *errVal, char *errorDesc, uint32_t descLen)
{
    HKS_IF_TRUE_RETURN_VOID(errVal == NULL || errorDesc == NULL || descLen == 0)
    
    HksMutex *mutex = GetUkeyGlobalMutex();
    if (mutex == NULL) {
        *errVal = 0;
        errorDesc[0] = '\0';
        return;
    }
    
    HksMutexLock(mutex);

    *errVal = g_ukeyGlobalInfo.errVal;
    uint32_t len = strlen(g_ukeyGlobalInfo.errorDesc);
    uint32_t copyLen = (len < descLen - 1) ? len : descLen - 1;
    (void)memcpy_s(errorDesc, descLen, g_ukeyGlobalInfo.errorDesc, copyLen);
    errorDesc[copyLen] = '\0';
    
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