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

#include "hks_auth_part_test.h"
#include "hks_auth_part_test_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::AuthPartTest {
class HksAuthPartTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAuthPartTest::SetUpTestCase(void)
{
}

void HksAuthPartTest::TearDownTestCase(void)
{
}

void HksAuthPartTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAuthPartTest::TearDown()
{
}

static const struct GenerateKeyCaseParam g_testGenKeyParams[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        3,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        5,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        6,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },
};

static const struct GenerateKeyCaseParam g_testSignKeyParams[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        3,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        5,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        6,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },
};

static const struct GenerateKeyCaseParam g_testVerifyKeyParams[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY},
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        3,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        5,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },

    {
        6,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },
};

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest001
 * @tc.desc: alg-RSA pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest001, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest001";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 0;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "RsaSignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest002
 * @tc.desc: alg-DSA pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest002, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest002";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 1;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "DsaSignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest003
 * @tc.desc: alg-ECC pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest003, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest003";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 2;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "EccSignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest004
 * @tc.desc: alg-ED25519 pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest004, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest004";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 3;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Ed25519SignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

#ifdef _USE_OPENSSL_
/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest005
 * @tc.desc: alg-SM2 pur-Sign.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest005, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest005";
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    uint32_t index = 4;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_SUCCESS) << "Sm2SignVerify SuccessCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}
#endif

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest006
 * @tc.desc: alg-RSA pur-Encrypt.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest006, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest006";
    uint32_t index = 5;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "RsaSignVerify FailureCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthSignVerifyTest006
 * @tc.desc: alg-ECC pur-Agree.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksAuthPartTest, HksAuthSignVerifyTest007, TestSize.Level0)
{
    const char *keyAliasString = "HksAuthSignVerifyTest007";
    uint32_t index = 6;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[index].params,
        sizeof(g_testGenKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[index].params,
        sizeof(g_testSignKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[index].params,
        sizeof(g_testVerifyKeyParams[index].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    if ((genParamSet != nullptr) || (signParamSet != nullptr) || (verifyParamSet != nullptr)) {
        ret = HksAuthSignVerifyTestNormalCase(keyAlias, genParamSet, signParamSet, verifyParamSet);
        EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "EccSignVerify FailureCase failed.";
    }

    /* Delete Key */
    ret = HksDeleteKey(&keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "DeleteKey failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&signParamSet);
    HksFreeParamSet(&verifyParamSet);
}
}
