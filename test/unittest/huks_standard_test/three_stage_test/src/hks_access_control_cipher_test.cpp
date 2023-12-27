/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_access_control_cipher_test.h"
#include "hks_access_control_test_common.h"
#include "hks_api.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
class HksAccessControlCipherTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlCipherTest::SetUpTestCase(void)
{
}

void HksAccessControlCipherTest::TearDownTestCase(void)
{
}

void HksAccessControlCipherTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlCipherTest::TearDown()
{
}

/* 001: gen aes for cipher; init for cipher */
static struct TestAccessCaseParams HKS_ACCESS_TEST_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initResult = HKS_SUCCESS
};

#ifdef _USE_OPENSSL_
/* mbedtls engine don't support SM4 alg */
/* 002: gen sm4 for cipher; init for cipher */
static struct TestAccessCaseParams HKS_ACCESS_TEST_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM4_KEY_SIZE_128 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initResult = HKS_SUCCESS
};
#endif

/* 003: gen aes for cipher; init for cipher */
static struct TestAccessCaseParams HKS_ACCESS_TEST_003_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
            { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = AAD_SIZE, .data = (uint8_t *)AAD_FOR_AES_GCM }},
            { .tag = HKS_TAG_AE_TAG, .blob = { .size = AEAD_SIZE, .data = (uint8_t *)AEAD_FOR_AES_GCM }},
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initResult = HKS_SUCCESS
};

/* 004: gen rsa for cipher; init for cipher */
static struct TestAccessCaseParams HKS_ACCESS_TEST_004_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/* 005: gen aes for cipher; invalid HKS_TAG_PURPOSE */
static struct TestAccessCaseParams HKS_ACCESS_TEST_005_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = 0 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initResult = HKS_SUCCESS
};

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest001
 * @tc.desc: alg-AES gen-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest001");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    ASSERT_EQ(CheckAccessCipherTest(HKS_ACCESS_TEST_001_PARAMS, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest002
 * @tc.desc: alg-AES gen-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.authtype: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest002, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    /* mbedtls engine don't support SM4 alg */
    HKS_LOG_I("Enter HksAccessCipherPartTest002");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    ASSERT_EQ(CheckAccessCipherTest(HKS_ACCESS_TEST_002_PARAMS, testIDMParams), HKS_SUCCESS);
#endif
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest003
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest004
 * @tc.desc: supports fine-grained access control, alg-SM4 gen-pur-Encrypt, and use access control.
 * @tc.type: FUNC
 * @tc.authtype: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest004, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    /* mbedtls engine don't support SM4 alg */
    HKS_LOG_I("Enter HksAccessCipherPartTest004");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_002_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
#endif
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest005
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, except keyAuthPurpose.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_ERROR_INVALID_PURPOSE
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest005");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest006
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, except keyAuthPurpose.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_ERROR_INVALID_PURPOSE
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest006");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_DECRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest007
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, except keyAuthPurpose.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_ERROR_INVALID_PURPOSE
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest007");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_DECRYPT | HKS_KEY_PURPOSE_ENCRYPT
        }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest008
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, genParams set mode.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result: HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest008");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM }
    );
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest009
 * @tc.desc: supports fine-grained access control, alg-RSA gen-pur-Encrypt, need to access control.
 * @tc.type: FUNC
 * @tc.authtype: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest009");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest010
 * @tc.desc: supports fine-grained access control, alg-RSA gen-pur-Encrypt, skip to access control.
 * @tc.type: FUNC
 * @tc.authtype: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest010");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest011
 * @tc.desc: supports fine-grained access control, alg-RSA gen-pur-Encrypt, except keyAuthPurpose.
 * @tc.type: FUNC
 * @tc.authtype: FACE
 * @tc.result:HKS_ERROR_INVALID_PURPOSE
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest011");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_ERROR_INVALID_PURPOSE);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest012
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, genParams not set mode.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result: HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest012");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest013
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, invalid HKS_TAG_PURPOSE.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest013, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest0013");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_005_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksAccessControlCipherTest.HksAccessCipherPartTest014
 * @tc.desc: one stage api:HksEncrypt HksDecrypt do not support operate user-auth-key
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlCipherTest, HksAccessCipherPartTest014, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessCipherPartTest014");
    uint8_t alias[] = "testCheckAuthCipher";
    struct HksBlob keyAlias = { sizeof(alias), alias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_ACCESS_TEST_001_PARAMS.genParams.data(),
        HKS_ACCESS_TEST_001_PARAMS.genParams.size());
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // test encrypt
    struct HksParam cipherParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
    };
    struct HksParamSet *cipherParamSet = nullptr;
    ret = InitParamSet(&cipherParamSet, cipherParams, sizeof(cipherParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t plainData[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa5, 0xb8, 0xa3, 0x78, 0x1d,
        0x6d, 0x76, 0xe0, 0xb3, 0xf5, 0x6f, 0x43, 0x9d, 0xcf, 0x60, 0xf6, 0x0b, 0x3f, 0x64, 0x45, 0xa8,
        0x3f, 0x1a, 0x96, 0xf1, 0xa1, 0xa4, 0x5d, 0x3e, 0x2c, 0x3f, 0x13, 0xd7, 0x81, 0xf7, 0x2a, 0xb5,
        0x8d, 0x19, 0x3d, 0x9b, 0x96, 0xc7, 0x6a, 0x10, 0xf0, 0xaa, 0xbc, 0x91, 0x6f, 0x4d, 0xa7, 0x09,
    };
    struct HksBlob plainDataBlob = { .size = sizeof(plainData), .data = plainData };
    uint8_t outData[256] = {0};
    struct HksBlob outDataBlob = { .size = sizeof(outData), .data = outData };
    ret = HksEncrypt(&keyAlias, cipherParamSet, &plainDataBlob, &outDataBlob);
    (void)HksFreeParamSet(&cipherParamSet);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);

    // test decrypt
    struct HksParam cipherParams2[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t *)IV }},
    };
    struct HksParamSet *cipherParamSet2 = nullptr;
    ret = InitParamSet(&cipherParamSet2, cipherParams2, sizeof(cipherParams2) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksDecrypt(&keyAlias, cipherParamSet2, &plainDataBlob, &outDataBlob);
    (void)HksFreeParamSet(&cipherParamSet2);
    (void)HksDeleteKey(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
}