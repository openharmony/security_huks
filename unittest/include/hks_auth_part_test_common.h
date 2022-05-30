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

#ifndef HKS_AUTH_PART_TEST_COMMON_H
#define HKS_AUTH_PART_TEST_COMMON_H

#include <string>
#include "hks_three_stage_test_common.h"
namespace Unittest::AuthPartTest {
static const std::string g_inData = "Hks_Auth_Part_Test_0000000000000000000000000000000000000000000000000000000"
                                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                    "0000000000000000000000000000000000000000000000000000000000000000000000000_string";
static const uint32_t SIGN_COMMON_SIZE = 1024;
static const uint32_t HMAC_COMMON_SIZE = 256;
static const uint32_t X25519_COMMON_SIZE = 4096;
static const uint32_t DH_COMMON_SIZE = 2048;
static const uint32_t KEY_COMMON_SIZE = 1024;
static const uint32_t SM4_COMMON_SIZE = 256;

struct GenerateKeyCaseParam {
    uint32_t id;
    int32_t result;
    struct HksParam params[9];
};

int32_t HksAuthSignVerifyTestNormalCase(struct HksBlob keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *signParamSet, struct HksParamSet *verifyParamSet);
int32_t HksTestSignVerify(struct HksBlob *keyAlias, struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData, bool isSign);
int32_t  HksAuthAgreeFinish(const struct HksBlob *keyAlias, const struct HksBlob *publicKey,
    const struct HksParamSet *initParamSet, const struct HksParamSet *finishParamSet, struct HksBlob *outData);
void HksAuthAgreeFreeParamSet(struct HksParamSet *paramSet1, struct HksParamSet *paramSet2,
    struct HksParamSet *paramSet3, struct HksParamSet *paramSet4, struct HksParamSet *paramSet5);
void HksAuthAgreeFreeBlob(struct HksBlob *blob1, struct HksBlob *blob2, struct HksBlob *blob3, struct HksBlob *blob4);
int32_t HksAuthAgreeExport(const struct HksBlob *keyAlias1, const struct HksBlob *keyAlias2,
    struct HksBlob *publicKey1, struct HksBlob *publicKey2, const struct HksParamSet *genParamSet);
int32_t HksRsaCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText);
int32_t HksRsaCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData);
int32_t HksRsaCipherTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet, const struct HksBlob *inData);
int32_t HksAuthCipherTestEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *encryptParamSet, const struct HksBlob *inData, struct HksBlob *cipherText);
int32_t HksAuthCipherTestDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *decryptParamSet, const struct HksBlob *cipherText, struct HksBlob *plainText,
    const struct HksBlob *inData);
int32_t HksAuthCipherTestCaseOther(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *encryptParamSet, struct HksParamSet *decryptParamSet);
int32_t HksHmacTestCase(const struct HksBlob *keyAlias, struct HksParamSet *genParamSet,
    struct HksParamSet *hmacParamSet);
}
#endif // HKS_AUTH_PART_TEST_COMMON_H

