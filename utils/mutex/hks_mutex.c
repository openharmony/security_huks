/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_mutex.h"

#include <pthread.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

struct HksMutex {
    pthread_mutex_t mutex;
};

HksMutex *HksMutexCreate(void)
{
    HksMutex *mutex = (HksMutex *)HksMalloc(sizeof(HksMutex));
    if (mutex == NULL) {
        HKS_LOG_E("HksMalloc HksMutex fail");
        return NULL;
    }
    int result = pthread_mutex_init(&mutex->mutex, NULL);
    if (result != 0) {
        HKS_LOG_E("pthread_mutex_init fail %" LOG_PUBLIC "d", result);
        HKS_FREE(mutex);
        mutex = NULL;
    }
    return mutex;
}

int32_t HksMutexLock(HksMutex *mutex)
{
    HKS_IF_NULL_LOGE_RETURN(mutex, HKS_ERROR_NULL_POINTER, "NULL mutex in HksMutexLock")

    int result = pthread_mutex_lock(&mutex->mutex);
    if (result != 0) {
        HKS_LOG_E("pthread_mutex_lock fail %" LOG_PUBLIC "d", result);
    }
    return result;
}

int32_t HksMutexUnlock(HksMutex *mutex)
{
    HKS_IF_NULL_LOGE_RETURN(mutex, HKS_ERROR_NULL_POINTER, "NULL mutex in HksMutexUnlock")

    int result = pthread_mutex_unlock(&mutex->mutex);
    if (result != 0) {
        HKS_LOG_E("pthread_mutex_unlock fail %" LOG_PUBLIC "d", result);
    }
    return result;
}

void HksMutexClose(HksMutex *mutex)
{
    if (mutex == NULL) {
        HKS_LOG_E("NULL mutex in HksMutexClose");
        return;
    }

    int result = pthread_mutex_destroy(&mutex->mutex);
    if (result != 0) {
        HKS_LOG_E("pthread_mutex_destroy fail %" LOG_PUBLIC "d", result);
    }
    HKS_FREE(mutex);
}
