/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HKS_TYPE_INNER_H
#define HKS_TYPE_INNER_H

#include "hks_type.h"
#include "securec.h"

#define HANDLE_SIZE              8
#define DEFAULT_AUTH_TIMEOUT     5

/* EnrolledIdInfo stored format: |-enrolledId len-|-enrolledId1 type-|-enrolledId1 value-|...|  */
#define ENROLLED_ID_INFO_MIN_LEN  (sizeof(uint32_t) + (sizeof(uint32_t) + sizeof(uint64_t)))

enum HksUserAuthResult {
    HKS_AUTH_RESULT_NONE = -2, // not support user auth
    HKS_AUTH_RESULT_INIT = -1,
    HKS_AUTH_RESULT_SUCCESS = 0,
    HKS_AUTH_RESULT_FAILED = 1,
};

#endif /* HKS_TYPE_INNER_H */
