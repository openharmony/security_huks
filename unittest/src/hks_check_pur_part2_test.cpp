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

#include "hks_check_pur_part_test.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::CheckPurposeTest {
class HksCheckPurPart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckPurPart2Test::SetUpTestCase(void)
{
}

void HksCheckPurPart2Test::TearDownTestCase(void)
{
}

void HksCheckPurPart2Test::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksCheckPurPart2Test::TearDown()
{
}

/* 009: gen rsa for sign; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_009_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initResult = HKS_SUCCESS
};

/* 010: gen dsa for sign; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_010_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 011: gen ecc for sign; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_011_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_521 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initResult = HKS_SUCCESS
};

/* 012: gen ed25519 for sign; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_012_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 013: gen sm2 for sign; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_013_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 014: gen rsa for encrypt; init for encrypt */
const TestPurposeCaseParams HKS_PURPOE_TEST_014_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_1024 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initResult = HKS_SUCCESS
};

/* 015: gen aes for encrypt; init for encrypt */
const TestPurposeCaseParams HKS_PURPOE_TEST_015_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 016: gen sm4 for encrypt; init for encrypt */
const TestPurposeCaseParams HKS_PURPOE_TEST_016_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV } },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 017: gen x25519 for agree; init for agree */
const TestPurposeCaseParams HKS_PURPOE_TEST_017_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 018: gen ecc for agree; init for agree */
const TestPurposeCaseParams HKS_PURPOE_TEST_018_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_224 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 019: gen dh for agree; init for agree */
const TestPurposeCaseParams HKS_PURPOE_TEST_019_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 020: gen sm3 for mac; init for mac */
const TestPurposeCaseParams HKS_PURPOE_TEST_020_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

/* 021: gen hmac for mac; init for mac */
const TestPurposeCaseParams HKS_PURPOE_TEST_021_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_SUCCESS
};

static int32_t CheckPurposeTest(const TestPurposeCaseParams &testCaseParams)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, testCaseParams.genParams.data(), testCaseParams.genParams.size());
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("InitParamSet(gen) failed, ret : %d", ret);
        return ret;
    }

    uint8_t alias[] = "testCheckPurpose";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        HKS_LOG_I("HksGenerateKey failed, ret : %d", ret);
        return ret;
    }

    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, testCaseParams.initParams.data(), testCaseParams.initParams.size());
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        HKS_LOG_I("InitParamSet(init) failed, ret : %d", ret);
        return ret;
    }

    uint64_t handle = 0;
    struct HksBlob handleBlob = { sizeof(handle), (uint8_t *)handle };
    ret = HksInit(&keyAlias, initParamSet, &handleBlob);
    EXPECT_EQ(ret, testCaseParams.initResult);

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&initParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);

    return (ret == testCaseParams.initResult) ? HKS_SUCCESS : HKS_FAILURE;
}

/**
 * @tc.name: HksCheckPurposeTest.HksCheckPurposeTest009
 * @tc.desc: alg-RSA gen-pur-Sign init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest009");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_009_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest010
 * @tc.desc: alg-DSA gen-pur-Sign init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest010");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_010_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckPurposeTest.HksCheckPurposeTest011
 * @tc.desc: alg-ECC gen-pur-Sign init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest011");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_011_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest012
 * @tc.desc: alg-ED25519 gen-pur-Sign init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest012");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_012_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckPurposeTest.HksCheckPurposeTest013
 * @tc.desc: alg-SM2 gen-pur-Sign init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest013, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest013");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_013_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest014
 * @tc.desc: alg-RSA gen-pur-Encrypt init-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest014, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest014");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_014_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksCheckPurposeTest.HksCheckPurposeTest015
 * @tc.desc: alg-AES gen-pur-Encrypt init-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest015, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest015");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_015_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest016
 * @tc.desc: alg-SM4 gen-pur-Encrypt init-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest016, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest016");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_016_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest017
 * @tc.desc: alg-X25519 gen-pur-Agree init-pur-Agree.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest017, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest017");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_017_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest018
 * @tc.desc: alg-ECC gen-pur-Agree init-pur-Agree.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest018, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest018");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_018_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest019
 * @tc.desc: alg-DH gen-pur-Agree init-pur-Agree.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest019, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest019");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_019_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest020
 * @tc.desc: alg-SM3 gen-pur-Mac init-pur-Mac.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest020, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest020");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_020_PARAMS), HKS_SUCCESS);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest021
 * @tc.desc: alg-HMAC gen-pur-Mac init-pur-Mac.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurPart2Test, HksCheckPurTest021, TestSize.Level0)
{
    HKS_LOG_I("Enter HksCheckPurposeTest021");
    EXPECT_EQ(CheckPurposeTest(HKS_PURPOE_TEST_021_PARAMS), HKS_SUCCESS);
}
}

