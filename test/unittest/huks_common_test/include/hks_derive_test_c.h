/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "hks_derive_test.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

#define DEFAULT_DERIVE_SIZE 32
#define DEFAULT_INFO_SIZE 55
#define DEFAULT_SALT_SIZE 16

static const struct HksTestDeriveParams g_testDeriveParams[] = {
    /* hkdf-sha256-salt-info */
    { 0, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_DERIVE,
            true, HKS_DIGEST_SHA256,
            false, 0,
            false, 0,
            false, 0 },
        { 0 },
        {
            true, /* derive params */
            true, HKS_ALG_HKDF,
            true, HKS_KEY_PURPOSE_DERIVE,
            true, HKS_DIGEST_SHA256,
            false, 0,
            true, DEFAULT_SALT_SIZE,
            true, DEFAULT_INFO_SIZE,
            false, true },
        {
            true, DEFAULT_DERIVE_SIZE, true, DEFAULT_DERIVE_SIZE },
        {
            false, 0, false, 0 }
    },

    /* local: hkdf-sha256-salt-info */
    { 1, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_DERIVE,
            true, HKS_DIGEST_SHA256,
            false, 0,
            false, 0,
            true, HKS_STORAGE_TEMP },
        { 0 },
        {
            true, /* derive params */
            true, HKS_ALG_HKDF,
            true, HKS_KEY_PURPOSE_DERIVE,
            true, HKS_DIGEST_SHA256,
            false, 0,
            true, DEFAULT_SALT_SIZE,
            true, DEFAULT_INFO_SIZE,
            true, false },
        {
            true, DEFAULT_DERIVE_SIZE, true, DEFAULT_DERIVE_SIZE },
        {
            true, DEFAULT_LOCAL_KEY_SIZE, true, DEFAULT_LOCAL_KEY_SIZE }
    },
};
