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

#include "hks_access_control_user_mode_test.h"
#include "hks_access_control_test_common.h"
#include "hks_api.h"
#include "hks_test_adapt_for_de.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
class HksAccessControlUserAuthModeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlUserAuthModeTest::SetUpTestCase(void)
{
}

void HksAccessControlUserAuthModeTest::TearDownTestCase(void)
{
}

void HksAccessControlUserAuthModeTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlUserAuthModeTest::TearDown()
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
            { .tag = HKS_TAG_USER_AUTH_MODE, .uint32Param = HKS_USER_AUTH_MODE_COAUTH },
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
            { .tag = HKS_TAG_USER_AUTH_MODE, .uint32Param = HKS_USER_AUTH_MODE_COAUTH },
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
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_USER_AUTH_MODE, .uint32Param = HKS_USER_AUTH_MODE_LOCAL },
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

/* 003: gen aes for cipher; init for cipher */
static struct TestAccessCaseParams HKS_ACCESS_TEST_004_PARAMS = {
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

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest001
 * @tc.desc: alg-AES gen-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: COAUTH
 * @tc.authtokentype: LOCAL
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest001");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 0
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(HKS_ACCESS_TEST_001_PARAMS, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest002
 * @tc.desc: alg-AES gen-pur-Encrypt.
 * @tc.type: FUNC
 * @tc.authtype: FINGERPRINT
 * @tc.authmode: COAUTH
 * @tc.authtokentype: LOCAL
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest002, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    /* mbedtls engine don't support SM4 alg */
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest002");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4,
        .tokenType = 0
    };
    ASSERT_EQ(CheckAccessCipherTest(HKS_ACCESS_TEST_002_PARAMS, testIDMParams), HKS_SUCCESS);
#endif
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest003
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: COAUTH
 * @tc.authtokentype: LOCAL_RESIGN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest004
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: COAUTH
 * @tc.authtokentype: COAUTH
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest004");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest005
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: LOCAL
 * @tc.authtokentype: LOCAL
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest005");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 0
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest006
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: LOCAL
 * @tc.authtokentype: LOCAL_RESIGN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest006");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest007
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: LOCAL
 * @tc.authtokentype: COAUTH
 * @tc.result:HKS_FAILURE
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest007");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_FAILURE);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest008
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: NULL
 * @tc.authtokentype: LOCAL
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest008");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 0
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest009
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: NULL
 * @tc.authtokentype: LOCAL_RESIGN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest009");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 1
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest010
 * @tc.desc: supports fine-grained access control, alg-AES gen-pur-Encrypt, and skip access control.
 * @tc.type: FUNC
 * @tc.authtype: PIN
 * @tc.authmode: NULL
 * @tc.authtokentype: COAUTH
 * @tc.result:HKS_FAILURE
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlUserAuthModeTest, HksAccessUserAuthModePartTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessUserAuthModePartTest010");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1,
        .tokenType = 2
    };
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_004_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT }
    );
    ASSERT_EQ(CheckAccessCipherTest(testAccessCaseParams, testIDMParams), HKS_FAILURE);
}
}