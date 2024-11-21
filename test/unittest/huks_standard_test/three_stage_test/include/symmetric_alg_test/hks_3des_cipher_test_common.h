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

#ifndef HKS_3DES_CIPHER_TEST_COMMON_H
#define HKS_3DES_CIPHER_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"

namespace Unittest::Des3Cipher {
static const uint32_t DES3_COMMON_SIZE = 1024;
static const uint32_t IV_SIZE = 8;
static const uint32_t IV_SIZE_INVALID = 9;

static uint8_t IV[IV_SIZE] = { 0 };
static uint8_t IV_INVALID[IV_SIZE_INVALID] = { 0 };

static const std::string g_inData = "Hks_3DES_Cipher_Test_00000000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const std::string g_inDataInvalid = "Hks_3DES_Cipher_Test_0000000000000000000000000000000000000000000000000000";

static struct HksBlob inData = {
    g_inData.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
};
static struct HksBlob inDataInvalid = {
    g_inDataInvalid.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inDataInvalid.c_str()))
};

int32_t Hks3DesCipherTest(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

} // namespace Unittest::Des3Cipher
#endif // HKS_3DES_CIPHER_TEST_COMMON_H
