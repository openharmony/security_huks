/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_des_cipher_test_common.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::DesCipher {
int32_t HksDesCipherTest(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    uint8_t handle[sizeof(uint64_t)] = { 0 };
    struct HksBlob handleBlob = { sizeof(uint64_t), handle };
    int32_t ret = HksInitForDe(keyAlias, paramSet, &handleBlob, nullptr);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return TestUpdateLoopFinish(&handleBlob, paramSet, inData, outData);
}
}
