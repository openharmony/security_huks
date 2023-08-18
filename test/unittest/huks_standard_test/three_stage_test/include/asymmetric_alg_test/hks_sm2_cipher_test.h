/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HKS_SM2_CIPHER_TEST_H
#define HKS_SM2_CIPHER_TEST_H

#include <string>
#include <vector>
#include "hks_in_data_array_after_hash_test_common.h"
#include "hks_three_stage_test_common.h"
#include "native_huks_api.h"
#include "native_huks_param.h"
#include "native_huks_type.h"
#include "hks_errcode_adapter.h"

#define INDATA_LEN 8

namespace Unittest::Sm2Cipher {
static const uint32_t SM2_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_SM2_Sign_Verify_Test_000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "000000000000000000000000000000000000000000000000000000000000000000000000_string";

static const std::string g_inDataArr[] = {
    "SM2_12_00000",
    "SM2_14_0000000",
    "SM2_63_00000000000000000000000000000000000000000000000000000000",
    "SM2_64_000000000000000000000000000000000000000000000000000000000",
    "SM2_65_0000000000000000000000000000000000000000000000000000000000",
    "SM2_96_000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000",
    "SM2_128_00000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000",
    "SM2_256_00000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
};

struct TestCaseParam {
    uint32_t id;
    int32_t result;
    std::vector<struct HksParam> params;
};

struct GenEncryptDecryptParam {
    struct TestCaseParam gen;
    struct TestCaseParam encrypt;
    struct TestCaseParam decrypt;
};

int HksSm2CipherTest001(void);
int HksSm2CipherTest002(void);
int HksSm2CipherTest003(void);
int HksSm2CipherTest004(void);
}
#endif // HKS_SM2_CIPHER_TEST_H