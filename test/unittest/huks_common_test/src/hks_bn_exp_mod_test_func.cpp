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

#include "hks_bn_exp_mod_test_c.h"

int32_t TestValue()
{
    HKS_TEST_LOG_I("test value");
    uint8_t bufX[HKS_TEST_8] = { 0, 0, 0, 0, 0, 0, 0, 0x40 };
    uint8_t bufA[HKS_TEST_8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t bufE[HKS_TEST_2] = { 0, 2 };
    uint8_t bufN[HKS_TEST_8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t tmpBufX[HKS_TEST_8] = {0};
    struct HksBlob tmpX = { HKS_TEST_8, tmpBufX };
    struct HksBlob tmpA = { HKS_TEST_8, bufA };
    struct HksBlob tmpE = { HKS_TEST_2, bufE };
    struct HksBlob tmpN = { HKS_TEST_8, bufN };
    int32_t ret = HksBnExpModRun(&tmpX, &tmpA, &tmpE, &tmpN, 1);
    for (int i = 0; i < HKS_TEST_8; ++i) {
        HKS_TEST_LOG_I("%x, %x", tmpBufX[i], bufX[i]);
        HKS_TEST_ASSERT(tmpBufX[i] == bufX[i]);
    }
    return ret;
}
