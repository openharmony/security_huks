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

#include "hks_access_control_rsa_sign_verify_test.h"

#include "hks_access_control_rsa_sign_verify_test_common.h"

#include <gtest/gtest.h>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::AccessControlRsaSignVerify {
class HksAccessControlRsaSignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlRsaSignVerifyTest::SetUpTestCase(void)
{
}

void HksAccessControlRsaSignVerifyTest::TearDownTestCase(void)
{
}

void HksAccessControlRsaSignVerifyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAccessControlRsaSignVerifyTest::TearDown()
{
}

/*
mock:
secureUid = 1
enrollinfo: authtype = PIN, enrolledId = 1
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = FINGERPRINT, enrolledId = 2
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = FACE, enrolledId = 3
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_003_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = PIN, enrolledId = 1
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_004_PARAMS_01 = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },

        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initResult = HKS_SUCCESS
};

const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_004_PARAMS_02 = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 1 },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 1 },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = None, enrolledId = 1
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_005_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = 30 },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = 30 },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = 30 },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 0
enrollinfo: authtype = None, enrolledId = 0
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_006_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag =  HKS_TAG_AUTH_TIMEOUT, .uint32Param = 1 },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag =  HKS_TAG_AUTH_TIMEOUT, .uint32Param = 1 },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
            { .tag =  HKS_TAG_AUTH_TIMEOUT, .uint32Param = 1 },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = FINGERPRINT, enrolledId = 2
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_007_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .signParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA384 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/*
mock:
secureUid = 1
enrollinfo: authtype = PIN, enrolledId = 1
*/
const TestAccessCaseRSAParams HKS_ACCESS_TEST_RSA_SIGN_008_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .signParams =
        {
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .verifyParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_3072 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA512 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest001
 * @tc.desc: pin test.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest001");
    const IDMParams RSAIDMParams001 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(HKS_ACCESS_TEST_RSA_SIGN_001_PARAMS, RSAIDMParams001),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest002
 * @tc.desc: fingerprint test.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest002");
    const IDMParams RSAIDMParams002 = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(HKS_ACCESS_TEST_RSA_SIGN_002_PARAMS, RSAIDMParams002),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest003
 * @tc.desc: wrong token auth type.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest003");
    const IDMParams RSAIDMParams003 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 2
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestAbnormalCase(HKS_ACCESS_TEST_RSA_SIGN_003_PARAMS, RSAIDMParams003),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest004
 * @tc.desc: custom test.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest004");
    const IDMParams RSAIDMParams004 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    EXPECT_EQ(HksAcRsaSignTestCustomCase(HKS_ACCESS_TEST_RSA_SIGN_004_PARAMS_01,
        HKS_ACCESS_TEST_RSA_SIGN_004_PARAMS_02, RSAIDMParams004), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest005
 * @tc.desc: time stamp test.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest005");
    const IDMParams RSAIDMParams005 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(HKS_ACCESS_TEST_RSA_SIGN_005_PARAMS, RSAIDMParams005),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest006
 * @tc.desc: time out test.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest006");
    const IDMParams RSAIDMParams006 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 100,
        .authType = 1
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestAbnormalCase(HKS_ACCESS_TEST_RSA_SIGN_006_PARAMS, RSAIDMParams006),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest007
 * @tc.desc: fingerprint test, with access type as HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest007");
    const IDMParams RSAIDMParams002 = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(HKS_ACCESS_TEST_RSA_SIGN_007_PARAMS, RSAIDMParams002),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest008
 * @tc.desc: generate with pin, access with finger, expecting HKS_ERROR_KEY_AUTH_FAILED
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest008");
    const IDMParams RSAIDMParams003 = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    EXPECT_EQ(HksAcRsaSignVerifyTestAbnormalCase(HKS_ACCESS_TEST_RSA_SIGN_008_PARAMS, RSAIDMParams003),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest009
 * @tc.desc: supports fine-grained access control, pin test, verify need to access control.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest009, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest009");
    const IDMParams RSAIDMParams001 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct TestAccessCaseRSAParams testAccessCaseParams(HKS_ACCESS_TEST_RSA_SIGN_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY }
    );
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(testAccessCaseParams, RSAIDMParams001),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest010
 * @tc.desc: supports fine-grained access control, fingerprint test, verify need to access control.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest010, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest010");
    const IDMParams RSAIDMParams002 = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct TestAccessCaseRSAParams testAccessCaseParams(HKS_ACCESS_TEST_RSA_SIGN_002_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY }
    );
    EXPECT_EQ(HksAcRsaSignVerifyTestNormalCase(testAccessCaseParams, RSAIDMParams002),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest011
 * @tc.desc: supports fine-grained access control, face test, verify need to access control.
 * @tc.type: FUNC
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest011, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest011");
    const IDMParams RSAIDMParams003 = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 2
    };
    struct TestAccessCaseRSAParams testAccessCaseParams(HKS_ACCESS_TEST_RSA_SIGN_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY }
    );
    EXPECT_EQ(HksAcRsaSignVerifyTestAbnormalCase(testAccessCaseParams, RSAIDMParams003),
        HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlRsaSignVerifyTest.HksAcRsaSignVerifyTest012
 * @tc.desc: one stage api:HksSign HksVerify do not support operate user-auth-key
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlRsaSignVerifyTest, HksAcRsaSignVerifyTest012, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAcRsaSignVerifyTest0012");
    uint8_t alias[] = "testCheckAuthSigner";
    struct HksBlob keyAlias = { sizeof(alias), alias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_ACCESS_TEST_RSA_SIGN_001_PARAMS.genParams.data(),
        HKS_ACCESS_TEST_RSA_SIGN_001_PARAMS.genParams.size());
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // test sign
    struct HksParam signParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    };
    struct HksParamSet *signParamSet = nullptr;
    ret = InitParamSet(&signParamSet, signParams, sizeof(signParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t plainData[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa5, 0xb8, 0xa3, 0x78, 0x1d,
        0x6d, 0x76, 0xe0, 0xb3, 0xf5, 0x6f, 0x43, 0x9d, 0xcf, 0x60, 0xf6, 0x0b, 0x3f, 0x64, 0x45, 0xa8,
        0x3f, 0x1a, 0x96, 0xf1, 0xa1, 0xa4, 0x5d, 0x3e, 0x2c, 0x3f, 0x13, 0xd7, 0x81, 0xf7, 0x2a, 0xb5,
        0x8d, 0x19, 0x3d, 0x9b, 0x96, 0xc7, 0x6a, 0x10, 0xf0, 0xaa, 0xbc, 0x91, 0x6f, 0x4d, 0xa7, 0x09,
        0xb3, 0x57, 0x88, 0x19, 0x6f, 0x00, 0x4b, 0xad, 0xee, 0x34, 0x35,
    };
    struct HksBlob plainDataBlob = { sizeof(plainData), plainData };
    uint8_t signature[256] = {0};
    struct HksBlob signatureBlob = { sizeof(signature), signature };
    ret = HksSign(&keyAlias, signParamSet, &plainDataBlob, &signatureBlob);
    (void)HksFreeParamSet(&signParamSet);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);

    // test verify
    struct HksParam verifyParams2[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 },
    };
    struct HksParamSet *verifyParamSet2 = nullptr;
    ret = InitParamSet(&verifyParamSet2, verifyParams2, sizeof(verifyParams2) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksVerify(&keyAlias, verifyParamSet2, &plainDataBlob, &signatureBlob);
    (void)HksFreeParamSet(&verifyParamSet2);
    (void)HksDeleteKey(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
}
