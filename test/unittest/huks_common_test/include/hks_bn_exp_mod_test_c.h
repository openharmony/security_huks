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

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"

#define DEFAULT_X_SIZE 256
#define DEFAULT_A_SIZE 256
#define DEFAULT_E_SIZE 256
#define DEFAULT_N_SIZE 256
#define HKS_TEST_2 2
#define HKS_TEST_8 8

static const struct HksTestBnExpModParams g_testBnExpModParams[] = {
    /* normal case */
    { 0, HKS_SUCCESS, false,
        { true, DEFAULT_X_SIZE, true, DEFAULT_X_SIZE },
        { true, DEFAULT_A_SIZE, true, DEFAULT_A_SIZE },
        { true, DEFAULT_E_SIZE, true, DEFAULT_E_SIZE },
        { true, DEFAULT_N_SIZE, true, DEFAULT_N_SIZE }
    },
};

int32_t TestValue();