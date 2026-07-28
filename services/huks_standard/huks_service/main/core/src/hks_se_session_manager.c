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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_se_session_manager.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <securec.h>
#include <stdatomic.h>
#include <stdio.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_pthread_util.h"
#include "hks_template.h"
#include "huks_access.h"
#include "securec.h"
#include "hks_util.h"

#define MAX_SE_OPERATIONS_COUNT 1
#define SE_OPERATION_TIMEOUT_S 120
#define S_TO_MS 1000

static struct DoubleList g_seOperationList = { &g_seOperationList, &g_seOperationList };
static volatile atomic_uint_least32_t g_seOperationCount = 0;
static pthread_mutex_t g_seLock = PTHREAD_MUTEX_INITIALIZER;

static void DeleteSeKeyNode(uint64_t operationHandle)
{
    uint8_t *handle = (uint8_t *)HksMalloc(sizeof(uint64_t));
    HKS_IF_NULL_LOGE_RETURN_VOID(handle, "malloc failed")
    (void)memcpy_s(handle, sizeof(uint64_t), &operationHandle, sizeof(uint64_t));
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };

    struct HksParamSet *paramSet = NULL;
    if (HksInitParamSet(&paramSet) != HKS_SUCCESS) {
        HKS_FREE(handle);
        HKS_LOG_E("HksInitParamSet failed");
        return;
    }

    (void)HuksAccessAbort(&handleBlob, paramSet);

    HksFreeParamSet(&paramSet);
    HKS_FREE(handle);
}

static void FreeSeOperation(struct HksSeOperation **operation)
{
    if (operation == NULL || *operation == NULL) {
        return;
    }
    RemoveDoubleListNode(&(*operation)->listHead);
    HKS_FREE_BLOB((*operation)->processInfo.userId);
    HKS_FREE_BLOB((*operation)->processInfo.processName);
    HKS_FREE_BLOB((*operation)->errMsgBlob);
    HKS_FREE(*operation);
}

static void DeleteSeKeyNodeAndDecreaseGlobalCount(struct HksSeOperation *operation)
{
    DeleteSeKeyNode(operation->handle);
    FreeSeOperation(&operation);
    --g_seOperationCount;
    HKS_LOG_I("delete se keynode, count = %" LOG_PUBLIC "u", g_seOperationCount);
}

static bool IsSameProcessInfo(const struct HksProcessInfo *info, const struct HksSeOperation *op)
{
    return (info->userIdInt == op->processInfo.userIdInt) && (info->uidInt == op->processInfo.uidInt);
}

static bool DeleteTimeOutSeOperation(const struct HksProcessInfo *processInfo)
{
    struct HksSeOperation *operation = NULL;
    uint64_t curTime = 0;
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksElapsedRealTime(&curTime), false, "HksElapsedRealTime failed")
    HKS_DLIST_ITER(operation, &g_seOperationList) {
        HKS_IF_TRUE_CONTINUE(operation == NULL || operation->isInUse);
        if (IsSameProcessInfo(processInfo, operation)) {
            DeleteSeKeyNodeAndDecreaseGlobalCount(operation);
            return true;
        }
        if (operation->startTime + SE_OPERATION_TIMEOUT_S * S_TO_MS < curTime) {
            DeleteSeKeyNodeAndDecreaseGlobalCount(operation);
            return true;
        }
    }
    return false;
}

static int32_t InitSeOperationProcessInfo(const struct HksProcessInfo *processInfo,
    struct HksSeOperation *operation)
{
    operation->processInfo = *processInfo;
    operation->processInfo.userId.data = (uint8_t *)HksMalloc(processInfo->userId.size);
    HKS_IF_NULL_LOGE_RETURN(operation->processInfo.userId.data, HKS_ERROR_MALLOC_FAIL, "malloc userId failed")
    if (memcpy_s(operation->processInfo.userId.data, processInfo->userId.size,
        processInfo->userId.data, processInfo->userId.size) != EOK) {
        HKS_LOG_E("copy userId failed");
        HKS_FREE_BLOB(operation->processInfo.userId);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    operation->processInfo.processName.data = (uint8_t *)HksMalloc(processInfo->processName.size);
    if (operation->processInfo.processName.data == NULL) {
        HKS_LOG_E("malloc processName failed");
        HKS_FREE_BLOB(operation->processInfo.userId);
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(operation->processInfo.processName.data, processInfo->processName.size,
        processInfo->processName.data, processInfo->processName.size) != EOK) {
        HKS_LOG_E("copy processName failed");
        HKS_FREE_BLOB(operation->processInfo.userId);
        HKS_FREE_BLOB(operation->processInfo.processName);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    return HKS_SUCCESS;
}

int32_t HksCreateSeOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *operationHandle)
{
    (void)paramSet;
    HKS_IF_TRUE_LOGE_RETURN(operationHandle == NULL || operationHandle->size < sizeof(uint64_t),
        HKS_ERROR_INVALID_ARGUMENT, "invalid operationHandle")
    uint64_t handle = 0;
    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(&handle, sizeof(handle), operationHandle->data, sizeof(handle)) != EOK,
        HKS_ERROR_INSUFFICIENT_MEMORY, "copy handle failed")
    HKS_IF_TRUE_LOGE_RETURN((handle >> HKS_SE_HANDLE_MASK_BIT) == 0, HKS_ERROR_INVALID_ARGUMENT, "invalid se handle")

    struct HksSeOperation *operation = (struct HksSeOperation *)HksMalloc(sizeof(struct HksSeOperation));
    HKS_IF_NULL_LOGE_RETURN(operation, HKS_ERROR_MALLOC_FAIL, "malloc hks se operation failed")
    (void)memset_s(operation, sizeof(struct HksSeOperation), 0, sizeof(struct HksSeOperation));

    int32_t ret = InitSeOperationProcessInfo(processInfo, operation);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init se operation process info failed");
        HKS_FREE(operation);
        return ret;
    }

    if (HksElapsedRealTime(&operation->startTime) != HKS_SUCCESS) {
        HKS_LOG_E("HksElapsedRealTime failed");
        HKS_FREE_BLOB(operation->processInfo.userId);
        HKS_FREE_BLOB(operation->processInfo.processName);
        HKS_FREE_BLOB(operation->errMsgBlob);
        HKS_FREE(operation);
        return HKS_ERROR_INTERNAL_ERROR;
    }

    operation->handle = handle;
    operation->isInUse = false;

    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_seLock), HKS_ERROR_PTHREAD_MUTEX_LOCK_FAIL,
        "lock in HksCreateSeOperation fail");
    if (g_seOperationCount >= MAX_SE_OPERATIONS_COUNT && !DeleteTimeOutSeOperation(processInfo)) {
        ret = HKS_ERROR_SE_SESSION_EXCEED_LIMIT;
    } else {
        AddNodeAtDoubleListTail(&g_seOperationList, &operation->listHead);
        ++g_seOperationCount;
        ret = HKS_SUCCESS;
    }
    HKS_UNLOCK_OR_FAIL(g_seLock);
    if (ret == HKS_SUCCESS) {
        return ret;
    }

    HKS_FREE_BLOB(operation->processInfo.userId);
    HKS_FREE_BLOB(operation->processInfo.processName);
    HKS_FREE_BLOB(operation->errMsgBlob);
    HKS_FREE(operation);
    return ret;
}

struct HksSeOperation *HksQuerySeOperationAndMarkInUse(const struct HksProcessInfo *processInfo,
    const struct HksBlob *operationHandle)
{
    HKS_IF_TRUE_LOGE_RETURN(operationHandle == NULL || operationHandle->size < sizeof(uint64_t), NULL,
        "invalid operationHandle")
    uint64_t handle = 0;
    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(&handle, sizeof(handle), operationHandle->data, sizeof(handle)) != EOK, NULL,
        "copy handle failed")
    HKS_IF_TRUE_LOGE_RETURN((handle >> HKS_SE_HANDLE_MASK_BIT) == 0, NULL, "invalid se handle")

    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_seLock), NULL, "lock fail");
    struct HksSeOperation *operation = NULL;
    HKS_DLIST_ITER(operation, &g_seOperationList) {
        if (operation != NULL && operation->handle == handle && IsSameProcessInfo(processInfo, operation)) {
            HKS_IF_TRUE_LOGE_CONTINUE(operation->isInUse, "operation is in progress and cannot be used in parallel!")
            operation->isInUse = true;
            HKS_UNLOCK_OR_FAIL(g_seLock);
            return operation;
        }
    }
    HKS_UNLOCK_OR_FAIL(g_seLock);
    return NULL;
}

void HksMarkSeOperationUnUse(struct HksSeOperation *operation)
{
    HKS_IF_NULL_RETURN_VOID(operation)
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HKS_LOCK_OR_FAIL(g_seLock), "lock fail");
    if (!operation->isInUse) {
        HKS_LOG_E("ERROR! unexpected scene! operation->isInUse is false!");
    }
    operation->isInUse = false;
    HKS_UNLOCK_OR_FAIL(g_seLock);
}

void HksDeleteSeOperation(const struct HksBlob *operationHandle)
{
    HKS_IF_TRUE_LOGE_RETURN_VOID(operationHandle == NULL || operationHandle->size < sizeof(uint64_t),
        "invalid operationHandle")
    uint64_t handle = 0;
    HKS_IF_TRUE_LOGE_RETURN_VOID(memcpy_s(&handle, sizeof(handle), operationHandle->data, sizeof(handle)) != EOK,
        "copy handle failed")
    HKS_IF_TRUE_LOGE_RETURN_VOID((handle >> HKS_SE_HANDLE_MASK_BIT) == 0, "invalid se handle")

    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HKS_LOCK_OR_FAIL(g_seLock), "lock fail");
    struct HksSeOperation *operation = NULL;
    HKS_DLIST_ITER(operation, &g_seOperationList) {
        if (operation != NULL && operation->handle == handle) {
            HKS_IF_TRUE_LOGI_BREAK(operation->isInUse, "operation is in use, do not delete")
            FreeSeOperation(&operation);
            --g_seOperationCount;
            break;
        }
    }
    HKS_UNLOCK_OR_FAIL(g_seLock);
}

void HksDeleteSeSessionByProcessInfo(const struct HksProcessInfo *processInfo)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HKS_LOCK_OR_FAIL(g_seLock), "lock fail");
    struct HksSeOperation *operation = NULL;
    HKS_DLIST_SAFT_ITER(operation, &g_seOperationList) {
        if (operation != NULL && !operation->isInUse && IsSameProcessInfo(processInfo, operation)) {
            DeleteSeKeyNodeAndDecreaseGlobalCount(operation);
        }
    }
    HKS_UNLOCK_OR_FAIL(g_seLock);
}
