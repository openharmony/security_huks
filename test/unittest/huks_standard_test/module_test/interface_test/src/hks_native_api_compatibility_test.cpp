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

#include "hks_refresh_key_info_test.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include "hks_api.h"
#include "hks_log.h"
#include "hks_type.h"
#include "hks_param.h"
#include "native_huks_type.h"
#include "hks_errcode_adapter.h"

using namespace testing::ext;
namespace Unittest::HksNativeApiCompatibilityTest {
class HksNativeApiCompatibilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksNativeApiCompatibilityTest::SetUpTestCase(void)
{
}

void HksNativeApiCompatibilityTest::TearDownTestCase(void)
{
}

void HksNativeApiCompatibilityTest::SetUp()
{
}

void HksNativeApiCompatibilityTest::TearDown()
{
}

/**
 * @tc.name: HksNativeApiCompatibilityTest001
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyDigest equal to HksKeyDigest
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest001, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_NONE == (uint32_t)HKS_DIGEST_NONE, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_MD5 == (uint32_t)HKS_DIGEST_MD5, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SM3 == (uint32_t)HKS_DIGEST_SM3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA1 == (uint32_t)HKS_DIGEST_SHA1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA224 == (uint32_t)HKS_DIGEST_SHA224, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA256 == (uint32_t)HKS_DIGEST_SHA256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA384 == (uint32_t)HKS_DIGEST_SHA384, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA512 == (uint32_t)HKS_DIGEST_SHA512, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest002
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyDigest value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest002, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_NONE == 0, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_MD5 == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SM3 == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA1 == 10, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA224 == 11, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA256 == 12, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA384 == 13, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DIGEST_SHA512 == 14, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest003
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyPadding equal to HksKeyPadding
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest003, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_NONE == (uint32_t)HKS_PADDING_NONE, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_OAEP == (uint32_t)HKS_PADDING_OAEP, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PSS == (uint32_t)HKS_PADDING_PSS, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS1_V1_5 == (uint32_t)HKS_PADDING_PKCS1_V1_5, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS5 == (uint32_t)HKS_PADDING_PKCS5, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS7 == (uint32_t)HKS_PADDING_PKCS7, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest004
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyPadding value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest004, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_NONE == 0, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_OAEP == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PSS == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS1_V1_5 == 3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS5 == 4, true);
    ASSERT_EQ((uint32_t)OH_HUKS_PADDING_PKCS7 == 5, true);
}


/**
 * @tc.name: HksNativeApiCompatibilityTest005
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_CipherMode equal to HksCipherMode
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest005, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_ECB == (uint32_t)HKS_MODE_ECB, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CBC == (uint32_t)HKS_MODE_CBC, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CTR == (uint32_t)HKS_MODE_CTR, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_OFB == (uint32_t)HKS_MODE_OFB, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CCM == (uint32_t)HKS_MODE_CCM, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_GCM == (uint32_t)HKS_MODE_GCM, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest006
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_CipherMode value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest006, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_ECB == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CBC == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CTR == 3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_OFB == 4, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_CCM == 31, true);
    ASSERT_EQ((uint32_t)OH_HUKS_MODE_GCM == 32, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest007
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyPurpose equal to HksKeyPurpose
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest007, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_ENCRYPT == (uint32_t)HKS_KEY_PURPOSE_ENCRYPT, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_DECRYPT == (uint32_t)HKS_KEY_PURPOSE_DECRYPT, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_SIGN == (uint32_t)HKS_KEY_PURPOSE_SIGN, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_VERIFY == (uint32_t)HKS_KEY_PURPOSE_VERIFY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_DERIVE == (uint32_t)HKS_KEY_PURPOSE_DERIVE, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_WRAP == (uint32_t)HKS_KEY_PURPOSE_WRAP, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_UNWRAP == (uint32_t)HKS_KEY_PURPOSE_UNWRAP, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_MAC == (uint32_t)HKS_KEY_PURPOSE_MAC, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_AGREE == (uint32_t)HKS_KEY_PURPOSE_AGREE, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest008
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyPurpose value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest008, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_ENCRYPT == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_DECRYPT == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_SIGN == 4, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_VERIFY == 8, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_DERIVE == 16, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_WRAP == 32, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_UNWRAP == 64, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_MAC == 128, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_PURPOSE_AGREE == 256, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest009
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeySize equal to HksKeySize
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest009, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_512 == (uint32_t)HKS_RSA_KEY_SIZE_512, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_768 == (uint32_t)HKS_RSA_KEY_SIZE_768, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_1024 == (uint32_t)HKS_RSA_KEY_SIZE_1024, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_2048 == (uint32_t)HKS_RSA_KEY_SIZE_2048, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_3072 == (uint32_t)HKS_RSA_KEY_SIZE_3072, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_4096 == (uint32_t)HKS_RSA_KEY_SIZE_4096, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_224 == (uint32_t)HKS_ECC_KEY_SIZE_224, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_256 == (uint32_t)HKS_ECC_KEY_SIZE_256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_384 == (uint32_t)HKS_ECC_KEY_SIZE_384, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_521 == (uint32_t)HKS_ECC_KEY_SIZE_521, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_128 == (uint32_t)HKS_AES_KEY_SIZE_128, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_192 == (uint32_t)HKS_AES_KEY_SIZE_192, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_256 == (uint32_t)HKS_AES_KEY_SIZE_256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_512 == (uint32_t)HKS_AES_KEY_SIZE_512, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_2048 == (uint32_t)HKS_DH_KEY_SIZE_2048, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_3072 == (uint32_t)HKS_DH_KEY_SIZE_3072, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_4096 == (uint32_t)HKS_DH_KEY_SIZE_4096, true);
    ASSERT_EQ((uint32_t)OH_HUKS_SM2_KEY_SIZE_256 == (uint32_t)HKS_SM2_KEY_SIZE_256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_SM4_KEY_SIZE_128 == (uint32_t)HKS_SM4_KEY_SIZE_128, true);
    ASSERT_EQ((uint32_t)OH_HUKS_CURVE25519_KEY_SIZE_256 == (uint32_t)HKS_CURVE25519_KEY_SIZE_256, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest010
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyPurpose value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest010, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_512 == 512, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_768 == 768, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_1024 == 1024, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_2048 == 2048, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_3072 == 3072, true);
    ASSERT_EQ((uint32_t)OH_HUKS_RSA_KEY_SIZE_4096 == 4096, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_224 == 224, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_256 == 256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_384 == 384, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ECC_KEY_SIZE_521 == 521, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_128 == 128, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_192 == 192, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_256 == 256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_AES_KEY_SIZE_512 == 512, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_2048 == 2048, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_3072 == 3072, true);
    ASSERT_EQ((uint32_t)OH_HUKS_DH_KEY_SIZE_4096 == 4096, true);
    ASSERT_EQ((uint32_t)OH_HUKS_SM2_KEY_SIZE_256 == 256, true);
    ASSERT_EQ((uint32_t)OH_HUKS_SM4_KEY_SIZE_128 == 128, true);
    ASSERT_EQ((uint32_t)OH_HUKS_CURVE25519_KEY_SIZE_256 == 256, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest011
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyAlg equal to HksKeyAlg
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest011, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_RSA == (uint32_t)HKS_ALG_RSA, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ECC == (uint32_t)HKS_ALG_ECC, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_DSA == (uint32_t)HKS_ALG_DSA, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_AES == (uint32_t)HKS_ALG_AES, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_HMAC == (uint32_t)HKS_ALG_HMAC, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_HKDF == (uint32_t)HKS_ALG_HKDF, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_PBKDF2 == (uint32_t)HKS_ALG_PBKDF2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ECDH == (uint32_t)HKS_ALG_ECDH, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_X25519 == (uint32_t)HKS_ALG_X25519, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ED25519 == (uint32_t)HKS_ALG_ED25519, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_DH == (uint32_t)HKS_ALG_DH, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM2 == (uint32_t)HKS_ALG_SM2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM3 == (uint32_t)HKS_ALG_SM3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM4 == (uint32_t)HKS_ALG_SM4, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest012
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyAlg value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest012, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_RSA == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ECC == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_DSA == 3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_AES == 20, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_HMAC == 50, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_HKDF == 51, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_PBKDF2 == 52, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ECDH == 100, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_X25519 == 101, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_ED25519 == 102, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_DH == 103, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM2 == 150, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM3 == 151, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ALG_SM4 == 152, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest013
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_AlgSuite equal to HksAlgSuite
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest013, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING ==
        HKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING, true);
    ASSERT_EQ((uint32_t)OH_HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING ==
        HKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest014
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_AlgSuite value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest014, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING == 2, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest015
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyGenerateType equal to HksKeyGenerateType
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest015, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_DEFAULT == (uint32_t)HKS_KEY_GENERATE_TYPE_DEFAULT, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_DERIVE == (uint32_t)HKS_KEY_GENERATE_TYPE_DERIVE, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_AGREE == (uint32_t)HKS_KEY_GENERATE_TYPE_AGREE, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest016
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyGenerateType value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest016, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_DEFAULT == 0, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_DERIVE == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_GENERATE_TYPE_AGREE == 2, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest017
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyFlag equal to HksKeyFlag
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest017, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_IMPORT_KEY == (uint32_t)HKS_KEY_FLAG_IMPORT_KEY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_GENERATE_KEY == (uint32_t)HKS_KEY_FLAG_GENERATE_KEY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_AGREE_KEY == (uint32_t)HKS_KEY_FLAG_AGREE_KEY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_DERIVE_KEY == (uint32_t)HKS_KEY_FLAG_DERIVE_KEY, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest018
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyFlag value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest018, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_IMPORT_KEY == 1, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_GENERATE_KEY == 2, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_AGREE_KEY == 3, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_FLAG_DERIVE_KEY == 4, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest019
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyStorageType equal to HksKeyStorageType
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest019, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_STORAGE_TEMP == (uint32_t)HKS_STORAGE_TEMP, true);
    ASSERT_EQ((uint32_t)OH_HUKS_STORAGE_PERSISTENT == (uint32_t)HKS_STORAGE_PERSISTENT, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest020
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_KeyStorageType value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest020, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_STORAGE_TEMP == 0, true);
    ASSERT_EQ((uint32_t)OH_HUKS_STORAGE_PERSISTENT == 1, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest021
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_ImportKeyType equal to HksImportKeyType
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest021, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_TYPE_PUBLIC_KEY == (uint32_t)HKS_KEY_TYPE_PUBLIC_KEY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_TYPE_PRIVATE_KEY == (uint32_t)HKS_KEY_TYPE_PRIVATE_KEY, true);
    ASSERT_EQ((uint32_t)OH_HUKS_KEY_TYPE_KEY_PAIR == (uint32_t)HKS_KEY_TYPE_KEY_PAIR, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest022
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_ErrCode value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest022, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_SUCCESS == 0, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_PERMISSION_FAIL == 201, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_ILLEGAL_ARGUMENT == 401, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_NOT_SUPPORTED_API == 801, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_FEATURE_NOT_SUPPORTED == 12000001, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_MISSING_CRYPTO_ALG_ARGUMENT == 12000002, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_INVALID_CRYPTO_ALG_ARGUMENT == 12000003, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_FILE_OPERATION_FAIL == 12000004, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_COMMUNICATION_FAIL == 12000005, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_CRYPTO_FAIL == 12000006, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED == 12000007, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED == 12000008, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT == 12000009, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_SESSION_LIMIT == 12000010, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_ITEM_NOT_EXIST == 12000011, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_INTERNAL_ERROR == 12000012, true);
    ASSERT_EQ((uint32_t)OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST == 12000013, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest023
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_TagType equal to HksTagType
 * @tc.type: FUNC
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest023, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_INVALID == (uint32_t)HKS_TAG_TYPE_INVALID, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_INT == (uint32_t)HKS_TAG_TYPE_INT, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_UINT == (uint32_t)HKS_TAG_TYPE_UINT, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_ULONG == (uint32_t)HKS_TAG_TYPE_ULONG, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_BOOL == (uint32_t)HKS_TAG_TYPE_BOOL, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_BYTES == (uint32_t)HKS_TAG_TYPE_BYTES, true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest024
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:OH_Huks_TagType value compatibility
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest024, TestSize.Level0)
{
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_INVALID == 0 << 28, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_INT == 1 << 28, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_UINT == 2 << 28, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_ULONG == 3 << 28, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_BOOL == 4 << 28, true);
    ASSERT_EQ((uint32_t)OH_HUKS_TAG_TYPE_BYTES == 5 << 28, true);
}
/**
 * @tc.name: HksNativeApiCompatibilityTest060
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:struct OH_Huks_Result member and size
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest060, TestSize.Level0)
{
    ASSERT_EQ(sizeof(struct OH_Huks_Result) == sizeof(struct HksResult), true);
    struct OH_Huks_Result result;
    struct HksResult hksResult;
    ASSERT_EQ(sizeof(hksResult.errorCode) == sizeof(result.errorCode), true);
    ASSERT_EQ(sizeof(hksResult.errorMsg) == sizeof(result.errorMsg), true);
    ASSERT_EQ(sizeof(hksResult.data) == sizeof(result.data), true);
    
    ASSERT_EQ(sizeof(result.errorCode) == sizeof(int32_t), true);
    ASSERT_EQ(sizeof(result.errorMsg) == sizeof(const char *), true);
    ASSERT_EQ(sizeof(result.data) == sizeof(uint8_t *), true);
}

/**
 * @tc.name: HksNativeApiCompatibilityTest061
 * @tc.desc: normal case to test native api(OHOS-NDK) compatibility:struct OH_Huks_Blob member and size
 * @tc.require: issueI5UONG
 */
HWTEST_F(HksNativeApiCompatibilityTest, HksNativeApiCompatibilityTest061, TestSize.Level0)
{
    ASSERT_EQ(sizeof(struct OH_Huks_Blob) == sizeof(struct HksBlob), true);
    struct OH_Huks_Blob blob;
    struct HksBlob hksBlob;
    ASSERT_EQ(sizeof(blob.size) == sizeof(hksBlob.size), true);
    ASSERT_EQ(sizeof(blob.data) == sizeof(hksBlob.data), true);

    ASSERT_EQ(sizeof(blob.size) == sizeof(uint32_t), true);
    ASSERT_EQ(sizeof(blob.data) == sizeof(uint8_t *), true);
}
}
