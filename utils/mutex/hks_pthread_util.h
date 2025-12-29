/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HKS_PTHREAD_UTIL_H
#define HKS_PTHREAD_UTIL_H

#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>

#include "hks_log.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((unused)) static inline int32_t HksUtilLock(
    pthread_mutex_t *mutex, __attribute__((unused)) const char *name)
{
    int ret = pthread_mutex_lock(mutex);
    if (ret != 0) {
        __attribute__((unused)) int err = errno;
        HKS_LOG_E("pthread_mutex_lock %" LOG_PUBLIC "s fail %" LOG_PUBLIC "d errno %" LOG_PUBLIC "d msg %" LOG_PUBLIC
            "s", name, ret, err, strerror(err));
        return HKS_ERROR_PTHREAD_MUTEX_LOCK_FAIL;
    }
    return HKS_SUCCESS;
}
#define HKS_LOCK_OR_FAIL(mtx) HksUtilLock(&(mtx), #mtx)

__attribute__((unused)) static inline int32_t HksUtilUnlock(
    pthread_mutex_t *mutex, __attribute__((unused)) const char *name)
{
    int ret = pthread_mutex_unlock(mutex);
    if (ret != 0) {
        __attribute__((unused)) int err = errno;
        HKS_LOG_E("pthread_mutex_unlock %" LOG_PUBLIC "s fail %" LOG_PUBLIC "d errno %" LOG_PUBLIC "d msg %" LOG_PUBLIC
            "s", name, ret, err, strerror(err));
        return HKS_ERROR_PTHREAD_MUTEX_UNLOCK_FAIL;
    }
    return HKS_SUCCESS;
}
#define HKS_UNLOCK_OR_FAIL(mtx) HksUtilUnlock(&(mtx), #mtx)

#ifdef __cplusplus
}
#endif

#endif  // HKS_PTHREAD_UTIL_H