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

static struct HksBlob g_keyAlias01001 = {
    strlen("HksECDHAgreeKeyAliasTest001_1"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest001_1"
};
static struct HksBlob g_keyAlias02001 = {
    strlen("HksECDHAgreeKeyAliasTest001_2"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest001_2"
};
static struct HksBlob g_keyAliasFinal1001 = {
    strlen("HksECDHAgreeKeyAliasTest001_1_final"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest001_1_final"
};
static struct HksBlob g_keyAliasFinal2001 = {
    strlen("HksECDHAgreeKeyAliasTest001_2_final"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest001_2_final"
};


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
        HKS_SUCCESS,
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
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        7,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        8,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        9,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        10,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
            { .tag = HKS_TAG_PADDING, .uint32Param = 0 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = 0 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = 0 },
        },
    },

    {
        11,
        HKS_SUCCESS,
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

    {
        12,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        13,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        14,
        HKS_ERROR_INVALID_ALGORITHM,
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
        15,
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
        16,
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

    {
        17,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        18,
        HKS_ERROR_INVALID_ALGORITHM,
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
        19,
        HKS_ERROR_INVALID_ARGUMENT,
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

    {
        20,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_DIGEST_NONE },
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

static const struct GenerateKeyCaseParam g_testEncryptKeyParams[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
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
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testDecryptKeyParams[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
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
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testAgreeInitParams1[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
            { .tag = HKS_TAG_PADDING, .uint32Param = 0 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = 0 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = 0 },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testAgreeFinishParams1[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal1001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal1001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal1001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal1001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testAgreeInitParams2[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
            { .tag = HKS_TAG_PADDING, .uint32Param = 0 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = 0 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = 0 },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testAgreeFinishParams2[] = {
    {
        0,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal2001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal2001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal2001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_ALIAS, .blob = g_keyAliasFinal1001 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        4,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    },
};

static const struct GenerateKeyCaseParam g_testHmacParams[] = {
    {
        0,
        HKS_SUCCESS,
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

    {
        1,
        HKS_SUCCESS,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        2,
        HKS_ERROR_INVALID_ARGUMENT,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_MD5 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
            { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    },

    {
        3,
        HKS_ERROR_INVALID_ALGORITHM,
        {
            { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_DIGEST_NONE },
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
    uint32_t genIndex = 15;
    uint32_t signIndex = 5;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[signIndex].params,
        sizeof(g_testSignKeyParams[signIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[signIndex].params,
        sizeof(g_testVerifyKeyParams[signIndex].params) / sizeof(HksParam));
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
    uint32_t genIndex = 16;
    uint32_t cipherIndex = 6;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *signParamSet = nullptr;
    struct HksParamSet *verifyParamSet = nullptr;
    int32_t ret = HKS_FAILURE;
    struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&signParamSet, g_testSignKeyParams[cipherIndex].params,
        sizeof(g_testSignKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";
    ret = InitParamSet(&verifyParamSet, g_testVerifyKeyParams[cipherIndex].params,
        sizeof(g_testVerifyKeyParams[cipherIndex].params) / sizeof(HksParam));
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

/**
 * @tc.name: HksAuthPartTest.HksAuthCipherTest001
 * @tc.desc: alg-RSA pur-Encrypt.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthCipherTest001, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAuthCipherTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksBlob inData = { g_inData.length(),
                              (uint8_t *)g_inData.c_str() };
    uint32_t genIndex = 5;
    uint32_t cipherIndex = 0;

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_testEncryptKeyParams[cipherIndex].params,
        sizeof(g_testEncryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_testDecryptKeyParams[cipherIndex].params,
        sizeof(g_testDecryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksRsaCipherTestCase(&keyAlias, genParamSet, encryptParamSet, decryptParamSet, &inData);
    EXPECT_EQ(ret, HKS_SUCCESS) << "RsaCipherCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthCipherTest002
 * @tc.desc: alg-AES pur-Encrypt.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthCipherTest002, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAuthCipherTest002";
    uint32_t genIndex = 6;
    uint32_t cipherIndex = 1;
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_testEncryptKeyParams[cipherIndex].params,
        sizeof(g_testEncryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_testDecryptKeyParams[cipherIndex].params,
        sizeof(g_testDecryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAuthCipherTest(&keyAlias, genParamSet, encryptParamSet, decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "AesCipherCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}

#ifdef _USE_OPENSSL_
/**
* @tc.name: HksAuthPartTest.HksAuthCipherTest003
* @tc.desc: alg-SM4 pur-Encrypt.
* @tc.type: FUNC
*/
HWTEST_F(HksAuthPartTest, HksAuthCipherTest003, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAuthCipherTest003";
    uint32_t genIndex = 7;
    uint32_t cipherIndex = 2;
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_testEncryptKeyParams[cipherIndex].params,
        sizeof(g_testEncryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_testDecryptKeyParams[cipherIndex].params,
        sizeof(g_testDecryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAuthCipherTest(&keyAlias, genParamSet, encryptParamSet, decryptParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "Sm4CipherCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}
#endif

/**
 * @tc.name: HksAuthPartTest.HksAuthCipherTest004
 * @tc.desc: alg-AES pur-Agree.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksAuthPartTest, HksAuthCipherTest004, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAuthCipherTest004";
    uint32_t genIndex = 13;
    uint32_t cipherIndex = 3;
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_testEncryptKeyParams[cipherIndex].params,
        sizeof(g_testEncryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_testDecryptKeyParams[cipherIndex].params,
        sizeof(g_testDecryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAuthCipherTest(&keyAlias, genParamSet, encryptParamSet, decryptParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "AESCipherCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}


/**
 * @tc.name: HksAuthPartTest.HksAuthCipherTest005
 * @tc.desc: alg-DSA pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksAuthPartTest, HksAuthCipherTest005, TestSize.Level0)
{
    char tmpKeyAlias[] = "HksAuthCipherTest005";
    uint32_t genIndex = 14;
    uint32_t cipherIndex = 4;
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitParamSet(&encryptParamSet, g_testEncryptKeyParams[cipherIndex].params,
        sizeof(g_testEncryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(encrypt) failed.";

    struct HksParamSet *decryptParamSet = nullptr;
    ret = InitParamSet(&decryptParamSet, g_testDecryptKeyParams[cipherIndex].params,
        sizeof(g_testDecryptKeyParams[cipherIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(decrypt) failed.";

    ret = HksAuthCipherTest(&keyAlias, genParamSet, encryptParamSet, decryptParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "DSACipherCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    HksFreeParamSet(&decryptParamSet);
}


/**
 * @tc.name: HksAuthPartTest.HksAuthAgreeTest001
 * @tc.desc: alg-X25519, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthAgreeTest001, TestSize.Level0)
{
    uint32_t genIndex = 8;
    uint32_t agreeIndex = 0;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_testAgreeInitParams1[agreeIndex].params,
        sizeof(g_testAgreeInitParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_testAgreeInitParams2[agreeIndex].params,
        sizeof(g_testAgreeInitParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_testAgreeFinishParams2[agreeIndex].params,
        sizeof(g_testAgreeFinishParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_CURVE25519_KEY_SIZE_256, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_CURVE25519_KEY_SIZE_256, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksAuthAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = X25519_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = X25519_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksX25519AgreeFinish01 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksX25519AgreeFinish02 failed.";
    EXPECT_NE(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "error: outData01 equals outData02";

    HksDeleteKey(&g_keyAlias01001, genParamSet);
    HksDeleteKey(&g_keyAlias02001, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1001, NULL);
    HksDeleteKey(&g_keyAliasFinal2001, NULL);
    HksAuthAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksAuthAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthAgreeTest002
 * @tc.desc: alg-ECC, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthAgreeTest002, TestSize.Level0)
{
    uint32_t genIndex = 9;
    uint32_t agreeIndex = 1;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_testAgreeInitParams1[agreeIndex].params,
        sizeof(g_testAgreeInitParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_testAgreeInitParams2[agreeIndex].params,
        sizeof(g_testAgreeInitParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_ECC_KEY_SIZE_224, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_ECC_KEY_SIZE_224, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksAuthAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEcdhAgreeFinish01 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksEcdhAgreeFinish02 failed.";
    EXPECT_NE(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "error: outData01 equals outData02";

    HksDeleteKey(&g_keyAlias01001, genParamSet);
    HksDeleteKey(&g_keyAlias02001, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1001, NULL);
    HksDeleteKey(&g_keyAliasFinal2001, NULL);
    HksAuthAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksAuthAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}


/**
 * @tc.name: HksAuthPartTest.HksAuthAgreeTest003
 * @tc.desc: alg-DH, pur-AGREE
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthAgreeTest003, TestSize.Level0)
{
    uint32_t genIndex = 10;
    uint32_t agreeIndex = 2;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_testAgreeInitParams1[agreeIndex].params,
        sizeof(g_testAgreeInitParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_testAgreeInitParams2[agreeIndex].params,
        sizeof(g_testAgreeInitParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_testAgreeFinishParams2[agreeIndex].params,
        sizeof(g_testAgreeFinishParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_2048, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_2048, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksAuthAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = DH_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = DH_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish01 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksDhAgreeFinish02 failed.";
    EXPECT_NE(TestCmpKeyAliasHash(&outData01, &outData02), HKS_SUCCESS) << "error: outData01 equals outData02";

    HksDeleteKey(&g_keyAlias01001, genParamSet);
    HksDeleteKey(&g_keyAlias02001, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1001, NULL);
    HksDeleteKey(&g_keyAliasFinal2001, NULL);
    HksAuthAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksAuthAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthAgreeTest004
 * @tc.desc: alg-ECC, pur-Sign
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksAuthPartTest, HksAuthAgreeTest004, TestSize.Level0)
{
    uint32_t genIndex = 17;
    uint32_t agreeIndex = 3;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_testAgreeInitParams1[agreeIndex].params,
        sizeof(g_testAgreeInitParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params)  / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_testAgreeInitParams2[agreeIndex].params,
        sizeof(g_testAgreeInitParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_testAgreeFinishParams2[agreeIndex].params,
        sizeof(g_testAgreeFinishParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_DH_KEY_SIZE_4096, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksAuthAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksEccAgree1 FailureCase failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksEccAgree2 FailureCase failed.";

    HksDeleteKey(&g_keyAlias01001, genParamSet);
    HksDeleteKey(&g_keyAlias02001, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1001, NULL);
    HksDeleteKey(&g_keyAliasFinal2001, NULL);
    HksAuthAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksAuthAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthAgreeTest005
 * @tc.desc: alg-DSA, pur-AGREE
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksAuthPartTest, HksAuthAgreeTest005, TestSize.Level0)
{
    uint32_t genIndex = 18;
    uint32_t agreeIndex = 4;
    struct HksParamSet *genParamSet = nullptr;
    struct HksParamSet *initParamSet01 = nullptr;
    struct HksParamSet *finishParamSet01 = nullptr;
    struct HksParamSet *initParamSet02 = nullptr;
    struct HksParamSet *finishParamSet02 = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";
    ret = InitParamSet(&initParamSet01, g_testAgreeInitParams1[agreeIndex].params,
        sizeof(g_testAgreeInitParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)01 failed.";
    ret = InitParamSet(&finishParamSet01, g_testAgreeFinishParams1[agreeIndex].params,
        sizeof(g_testAgreeFinishParams1[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)01 failed.";
    ret = InitParamSet(&initParamSet02, g_testAgreeInitParams2[agreeIndex].params,
        sizeof(g_testAgreeInitParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init & update)02 failed.";
    ret = InitParamSet(&finishParamSet02, g_testAgreeFinishParams2[agreeIndex].params,
        sizeof(g_testAgreeFinishParams2[agreeIndex].params) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(finish)02 failed.";

    ret = HksGenerateKey(&g_keyAlias01001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey01 failed.";
    ret = HksGenerateKey(&g_keyAlias02001, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenerateKey02 failed.";

    struct HksBlob publicKey01 = { .size = HKS_RSA_KEY_SIZE_1024, .data = nullptr };
    struct HksBlob publicKey02 = { .size = HKS_RSA_KEY_SIZE_1024, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey01, publicKey01.size), HKS_SUCCESS) << "Malloc publicKey01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&publicKey02, publicKey02.size), HKS_SUCCESS) << "Malloc publicKey02 failed.";
    ret = HksAuthAgreeExport(&g_keyAlias01001, &g_keyAlias02001, &publicKey01, &publicKey02, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "ExportKey failed.";

    struct HksBlob outData01 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    struct HksBlob outData02 = { .size = KEY_COMMON_SIZE, .data = nullptr };
    EXPECT_EQ(MallocAndCheckBlobData(&outData01, outData01.size), HKS_SUCCESS) << "Malloc outData01 failed.";
    EXPECT_EQ(MallocAndCheckBlobData(&outData02, outData02.size), HKS_SUCCESS) << "Malloc outData02 failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias01001, &publicKey02, initParamSet01, finishParamSet01, &outData01);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksDsaAgree1 FailureCase failed.";
    ret = HksAuthAgreeFinish(&g_keyAlias02001, &publicKey01, initParamSet02, finishParamSet02, &outData02);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksDsaAgree2 FailureCase failed.";

    HksDeleteKey(&g_keyAlias01001, genParamSet);
    HksDeleteKey(&g_keyAlias02001, genParamSet);
    HksDeleteKey(&g_keyAliasFinal1001, NULL);
    HksDeleteKey(&g_keyAliasFinal2001, NULL);
    HksAuthAgreeFreeParamSet(genParamSet, initParamSet01, finishParamSet01, initParamSet02, finishParamSet02);
    HksAuthAgreeFreeBlob(&publicKey01, &publicKey02, &outData01, &outData02);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthHmacTest001
 * @tc.desc: alg-HMAC pur-MAC dig-sha1.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthHmacTest001, TestSize.Level0)
{
    uint32_t genIndex = 11;
    uint32_t hmacIndex = 0;
    char tmpKeyAlias[] = "HksAuthHmacTest001";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_testHmacParams[hmacIndex].params,
        sizeof(g_testHmacParams[hmacIndex].params) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HMAC Hmaccase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

#ifdef _USE_OPENSSL_
/**
 * @tc.name: HksAuthPartTest.HksAuthHmacTest002
 * @tc.desc: alg-SM3 pur-MAC dig-sm3.
 * @tc.type: FUNC
 */
HWTEST_F(HksAuthPartTest, HksAuthHmacTest002, TestSize.Level0)
{
    uint32_t genIndex = 12;
    uint32_t hmacIndex = 1;
    char tmpKeyAlias[] = "HksAuthHmacTest002";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_testHmacParams[hmacIndex].params,
        sizeof(g_testHmacParams[hmacIndex].params) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "SM3 Hmaccase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}
#endif

/**
 * @tc.name: HksAuthPartTest.HksAuthHmacTest003
 * @tc.desc: alg-HMAC pur-MAC dig-MD5.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksAuthPartTest, HksAuthHmacTest003, TestSize.Level0)
{
    uint32_t genIndex = 19;
    uint32_t hmacIndex = 2;
    char tmpKeyAlias[] = "HksAuthHmacTest003";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_testHmacParams[hmacIndex].params,
        sizeof(g_testHmacParams[hmacIndex].params) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HMAC FailureCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}

/**
 * @tc.name: HksAuthPartTest.HksAuthHmacTest004
 * @tc.desc: alg-AES pur-Encrypt dig-NONE.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksAuthPartTest, HksAuthHmacTest004, TestSize.Level0)
{
    uint32_t genIndex = 20;
    uint32_t hmacIndex = 3;
    char tmpKeyAlias[] = "HksAuthHmacTest004";
    struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_testGenKeyParams[genIndex].params,
        sizeof(g_testGenKeyParams[genIndex].params) / sizeof(HksParam));

    struct HksParamSet *hmacParamSet = nullptr;
    ret = InitParamSet(&hmacParamSet, g_testHmacParams[hmacIndex].params,
        sizeof(g_testHmacParams[hmacIndex].params) / sizeof(HksParam));

    ret = HksHmacTestCase(&keyAlias, genParamSet, hmacParamSet);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "AES FailureCase failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&hmacParamSet);
}
}
