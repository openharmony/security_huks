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
#include "hks_three_stage_test_common.h"
namespace Unittest::RsaSignVerify {
static const uint32_t RSA_COMMON_SIZE = 1024;
static const std::string g_inData = "Hks_RSA_Sign_Verify_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";

// g_inData md5 hash
static const uint8_t g_inDataAfterMd5Hash[] = {
    0x7E, 0x4F, 0x31, 0xD6, 0x42, 0x4A, 0xE0, 0x92, 0x11, 0xDD, 0xC0, 0x09, 0xE9, 0x82, 0x3C, 0x39,
};

// g_inData sha1 hash
static const uint8_t g_inDataAfterSha1Hash[] = {
    0x65, 0xA2, 0x75, 0xB3, 0x1A, 0x45, 0xAD, 0x2A, 0xE2, 0x5F, 0x87, 0xE0, 0x6B, 0xCB, 0xC6, 0x87,
    0x14, 0x2A, 0x5E, 0xA7,
};

// g_inData sha224 hash
static const uint8_t g_inDataAfterSha224Hash[] = {
    0x14, 0x48, 0x39, 0x7F, 0x2A, 0xB1, 0x65, 0x67, 0x89, 0xD0, 0x02, 0x13, 0x86, 0xD6, 0x01, 0x92,
    0x7A, 0xFB, 0x00, 0x33, 0xF3, 0x9C, 0x86, 0x0D, 0x1B, 0x75, 0x85, 0x8D,
};

// g_inData sha256 hash
static const uint8_t g_inDataAfterSha256Hash[] = {
    0x68, 0xD1, 0x5F, 0xE4, 0x46, 0xF7, 0xBF, 0x8D, 0x30, 0x91, 0x46, 0x53, 0x81, 0x49, 0xA0, 0xD5,
    0x39, 0xC7, 0xDC, 0x59, 0xE7, 0xF6, 0x42, 0x5D, 0x86, 0x09, 0x30, 0xD0, 0x3F, 0x4D, 0x91, 0x85,
};

// g_inData sha384 hash
static const uint8_t g_inDataAfterSha384Hash[] = {
    0x30, 0x94, 0x03, 0x05, 0xAB, 0xA6, 0x18, 0xA4, 0xB2, 0xF6, 0x03, 0x7A, 0x86, 0xB6, 0x9A, 0xA2,
    0xE0, 0xBD, 0xB7, 0x84, 0xD0, 0x86, 0xAF, 0xE3, 0x5B, 0x7A, 0x63, 0x60, 0xF8, 0x3D, 0xF8, 0xCE,
    0xE7, 0xC3, 0x83, 0x4C, 0x13, 0x60, 0x69, 0x48, 0x5C, 0xB3, 0x4A, 0xBA, 0xA7, 0x68, 0xF4, 0x43,
};

// g_inData sha512 hash
static const uint8_t g_inDataAfterSha512Hash[] = {
    0x4B, 0x1E, 0x22, 0x64, 0xA9, 0x89, 0x60, 0x1D, 0xEC, 0x78, 0xC0, 0x5D, 0xBE, 0x46, 0xAD, 0xCF,
    0x1C, 0x35, 0x16, 0x11, 0x34, 0x01, 0x4E, 0x9B, 0x7C, 0x00, 0x66, 0x0E, 0xCA, 0x09, 0xC0, 0xF3,
    0x91, 0x67, 0xED, 0x5E, 0x9A, 0xF7, 0xF7, 0x02, 0x27, 0xE5, 0xF2, 0xC7, 0xDD, 0x7D, 0x4F, 0xFD,
    0x3A, 0x8D, 0x2D, 0x96, 0xCE, 0x73, 0x23, 0x5B, 0xB4, 0x51, 0xED, 0x10, 0x70, 0x61, 0xE2, 0xC7,
};

static const uint8_t *g_inDataArrayAfterHash[] = {
    g_inDataAfterMd5Hash,    g_inDataAfterSha1Hash,
    g_inDataAfterSha224Hash, g_inDataAfterSha256Hash,
    g_inDataAfterSha384Hash, g_inDataAfterSha512Hash,
};

static const uint32_t g_inDataArrayAfterHashLen[] = {16, 20, 28, 32, 48, 64};

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
} // namespace Unittest::RsaSignVerify
#endif // HKS_RSA_SIGN_VERIFY_TEST_COMMON_H