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

#ifndef HKS_SE_SESSION_MANAGER_H
#define HKS_SE_SESSION_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include "hks_double_list.h"
#include "hks_event_info.h"
#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

struct HksSeOperation {
    struct DoubleList listHead;
    uint64_t handle;
    bool isInUse;
    uint64_t startTime;
    struct HksProcessInfo processInfo;
    HksEventInfo eventInfo;
    struct HksBlob errMsgBlob;
};

int32_t HksCreateSeOperation(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *operationHandle);

struct HksSeOperation *HksQuerySeOperationAndMarkInUse(const struct HksProcessInfo *processInfo,
    const struct HksBlob *operationHandle);

void HksMarkSeOperationUnUse(struct HksSeOperation *operation);

void HksDeleteSeOperation(const struct HksBlob *operationHandle);

void HksDeleteSeSessionByProcessInfo(const struct HksProcessInfo *processInfo);

#ifdef __cplusplus
}
#endif

#endif /* HKS_SE_SESSION_MANAGER_H */
