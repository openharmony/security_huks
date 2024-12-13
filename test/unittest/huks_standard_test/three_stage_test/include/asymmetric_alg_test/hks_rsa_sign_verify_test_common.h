/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HKS_RSA_SIGN_VERIFY_TEST_COMMON_H
#define HKS_RSA_SIGN_VERIFY_TEST_COMMON_H

#include <string>
#include "hks_in_data_array_after_hash_test_common.h"
#include "hks_three_stage_test_common.h"
namespace Unittest::RsaSignVerify {
static const uint32_t RSA_COMMON_SIZE = 1024;
static const uint32_t RSA_FLEX_KEY_SIZE_1536 = 1536;
static const uint32_t RSA_INVALID_FLEX_KEY_SIZE_1540 = 1540;
static const std::string g_inData = "Hks_RSA_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static struct HksBlob inData = {
    (uint32_t)g_inData.length(),
    const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(g_inData.c_str()))
};

int32_t HksRsaSignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);

int32_t HksRsaSignVerifyTestNormalAnotherCase(struct HksBlob keyAlias,
    struct HksParamSet *genParamSet, struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);

int32_t HksRsaSignVerifyTestParamAbsentCase(struct HksBlob keyAlias,
    struct HksParamSet *genParamSet, struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);

int32_t HksRSASignVerifyTestAbnormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);
int32_t HksRSASignVerifyTestAbnormalCaseNoPadding(struct HksBlob keyAlias,
    struct HksParamSet *genParamSet, struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);
int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, bool isSign);
int32_t HksRsaSignVerifyTestParamPSSaltLenFailureCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);
int32_t HksRsaSignTest(struct HksBlob *keyAlias, struct HksParamSet *signParamSet, struct HksBlob *plaintext,
    struct HksBlob *signature);
int32_t HksRsaVerifyTest(struct HksBlob *keyAlias, struct HksParamSet *verifyParamSet, struct HksBlob *plaintext,
    struct HksBlob *signature, struct HksBlob *outData);
} // namespace Unittest::RsaSignVerify
#endif // HKS_RSA_SIGN_VERIFY_TEST_COMMON_H