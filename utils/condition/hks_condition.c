/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hks_condition.h"

#include "hks_mem.h"
#include "hks_template.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct HksCondition {
    volatile atomic_bool notified;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

#define HKS_LOG_ERRNO(msg, ret) ({ int currentErrno = errno; \
    HKS_LOG_E(msg " %" LOG_PUBLIC "d, errno %" LOG_PUBLIC "d, strerror %" LOG_PUBLIC "s", \
        (ret), currentErrno, strerror(currentErrno)); })

int32_t HksConditionWait(HksCondition *condition)
{
    HKS_IF_NULL_LOGE_RETURN(condition, -1, "HksConditionWait condition is NULL!")

    int32_t ret = pthread_mutex_lock(&condition->mutex);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionWait pthread_mutex_lock fail!", ret);
        return ret;
    }
    if (atomic_load(&condition->notified)) {
        int unlockRet = pthread_mutex_unlock(&condition->mutex);
        if (unlockRet != 0) {
            HKS_LOG_ERRNO("HksConditionWait notified pthread_mutex_unlock fail!", unlockRet);
        }
        return 0;
    } else {
        HKS_LOG_I("HksConditionWait begin wait...");
        ret = pthread_cond_wait(&condition->cond, &condition->mutex);
        if (ret != 0) {
            HKS_LOG_ERRNO("HksConditionWait pthread_cond_wait fail!", ret);
        }
        int unlockRet = pthread_mutex_unlock(&condition->mutex);
        if (unlockRet != 0) {
            HKS_LOG_ERRNO("HksConditionWait waited pthread_mutex_unlock fail!", unlockRet);
        }
        return ret;
    }
}

int32_t HksConditionNotify(HksCondition *condition)
{
    HKS_IF_NULL_LOGE_RETURN(condition, -1, "HksConditionNotify condition is NULL!")

    int32_t ret = pthread_mutex_lock(&condition->mutex);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionNotify pthread_mutex_lock fail!", ret);
        return ret;
    }

    bool flag = false;
    if (atomic_compare_exchange_strong(&condition->notified, &flag, true)) {
        HKS_LOG_I("never pthread_cond_signal before, first time notify!");
    } else {
        HKS_LOG_W("do pthread_cond_signal again!");
    }

    ret = pthread_cond_signal(&condition->cond);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionNotify pthread_cond_signal fail!", ret);
    }
    int unlockRet = pthread_mutex_unlock(&condition->mutex);
    if (unlockRet != 0) {
        HKS_LOG_ERRNO("HksConditionNotify pthread_mutex_unlock fail!", unlockRet);
    }
    return ret;
}

int32_t HksConditionNotifyAll(HksCondition *condition)
{
    HKS_IF_NULL_LOGE_RETURN(condition, -1, "HksConditionNotifyAll condition is NULL!")

    int32_t ret = pthread_mutex_lock(&condition->mutex);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionNotifyAll pthread_mutex_lock fail!", ret);
        return ret;
    }

    bool flag = false;
    if (atomic_compare_exchange_strong(&condition->notified, &flag, true)) {
        HKS_LOG_I("never pthread_cond_broadcast before, first time notify!");
    } else {
        HKS_LOG_W("do pthread_cond_broadcast again!");
    }

    ret = pthread_cond_broadcast(&condition->cond);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionNotifyAll pthread_cond_broadcast fail!", ret);
    }
    int unlockRet = pthread_mutex_unlock(&condition->mutex);
    if (unlockRet != 0) {
        HKS_LOG_ERRNO("HksConditionNotifyAll pthread_mutex_unlock fail!", unlockRet);
    }
    return ret;
}

HksCondition *HksConditionCreate(void)
{
    HksCondition *condition = (HksCondition *)HksMalloc(sizeof(HksCondition));
    HKS_IF_NULL_RETURN(condition, NULL)
    atomic_store(&condition->notified, false);
    int32_t ret = pthread_mutex_init(&condition->mutex, NULL);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionCreate pthread_mutex_init fail!", ret);
        HKS_FREE(condition);
        return NULL;
    }

    pthread_condattr_t attr;
    int attrRet = pthread_condattr_init(&attr);
    if (attrRet != 0) {
        HKS_LOG_ERRNO("HksConditionCreate pthread_condattr_init fail!", attrRet);
    }
    ret = pthread_cond_init(&condition->cond, &attr);
    attrRet = pthread_condattr_destroy(&attr);
    if (attrRet != 0) {
        HKS_LOG_ERRNO("HksConditionCreate pthread_condattr_destroy fail!", attrRet);
    }
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionCreate pthread_cond_init fail!", ret);
        pthread_mutex_destroy(&condition->mutex);
        HKS_FREE(condition);
        return NULL;
    }
    return condition;
}

void HksConditionDestroy(HksCondition* condition)
{
    if (condition == NULL) {
        HKS_LOG_E("HksConditionDestroy condition is NULL!");
        return;
    }
    int ret = pthread_mutex_destroy(&condition->mutex);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionDestroy pthread_mutex_destroy fail!", ret);
    }
    ret = pthread_cond_destroy(&condition->cond);
    if (ret != 0) {
        HKS_LOG_ERRNO("HksConditionDestroy pthread_cond_destroy fail!", ret);
    }
    HKS_FREE(condition);
}

#ifdef __cplusplus
}
#endif