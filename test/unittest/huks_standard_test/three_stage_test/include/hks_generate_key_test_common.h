/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HKS_GENERATE_KEY_TEST_COMMON_H
#define HKS_GENERATE_KEY_TEST_COMMON_H

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

// gen wrap key with access control
static struct HksParam g_genParamsCommon001[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_IS_ALLOWED_WRAP,
        .boolParam = true
    }, {
        .tag = HKS_TAG_KEY_AUTH_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_USER_AUTH_TYPE,
        .uint32Param = HKS_USER_AUTH_TYPE_PIN | HKS_USER_AUTH_TYPE_FACE | HKS_USER_AUTH_TYPE_FINGERPRINT
    }, {
        .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
        .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
    }, {
        .tag = HKS_TAG_CHALLENGE_TYPE,
        .uint32Param = HKS_CHALLENGE_TYPE_NONE
    }
};

#endif
