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

#ifndef HKS_ML_DSA_SIGN_VERIFY_TEST_COMMON_H
#define HKS_ML_DSA_SIGN_VERIFY_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"

static const uint32_t ML_DSA_COMMON_SIZE = 4700;
static const uint32_t ML_DSA_MESSAGE_MAX_SIZE = 102400;
static const std::string g_inData = "Hks_ML_DSA_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const struct HksBlob inData = {
    (uint32_t)g_inData.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
};

static const std::string g_inDataInvalid = std::string(ML_DSA_MESSAGE_MAX_SIZE, 'a') + '0';
static const struct HksBlob inDataInvalid = {
    (uint32_t)g_inDataInvalid.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inDataInvalid.c_str()))
};

int32_t HksMlDsaTestSignVerify(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

#endif // HKS_ML_DSA_SIGN_VERIFY_TEST_COMMON_H