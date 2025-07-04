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

#include "hks_access_control_derive_test.h"
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
class HksAccessControlDeriveTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlDeriveTest::SetUpTestCase(void)
{
}

void HksAccessControlDeriveTest::TearDownTestCase(void)
{
}

void HksAccessControlDeriveTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlDeriveTest::TearDown()
{
    std::system("find /data/service/el1/public/huks_service -user root -delete");
}

/* 001: gen hkdf for derive; init for derive */
static struct TestAccessCaseParams HKS_ACCESS_TEST_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_32 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NONE },
        },
    .initResult = HKS_SUCCESS
};

static struct HksBlob g_keyAliasFinish001 = {
    strlen("HksHKDFDeriveKeyAliasFinalTest001"),
    (uint8_t *)"HksHKDFDeriveKeyAliasFinalTest001"
};

static struct HksParam g_deriveAccessFinish001[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinish001
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    }
};

/* 002: gen pbkdf2 for derive; init for derive */
static struct TestAccessCaseParams HKS_ACCESS_TEST_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_PBKDF2 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_ITERATION, .int32Param = DERIVE_ITERATION },
            { .tag = HKS_TAG_SALT, .blob = { sizeof(g_saltdata), (uint8_t *)g_saltdata }},
            { .tag = HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_32 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_CUSTOM },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0 },
        },
    .initResult = HKS_SUCCESS
};
static struct HksBlob g_keyAliasFinish002 = {
    strlen("HksHKDFDeriveKeyAliasFinalTest002"),
    (uint8_t *)"HksHKDFDeriveKeyAliasFinalTest002"
};

static struct HksParam g_deriveAccessFinish002[] = {
    {
        .tag =  HKS_TAG_KEY_STORAGE_FLAG,
        .uint32Param = HKS_STORAGE_PERSISTENT
    }, {
        .tag =  HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinish002
    }, {
        .tag =  HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag =  HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    }, {
        .tag =  HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
    }
};

/**
 * @tc.name: HksAccessControlDeriveTest.HksAccessDerivePartTest001
 * @tc.desc: alg-HKDF gen-pur-Derive.
 * @tc.type: FUNC
 * @tc.auth_type: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlDeriveTest, HksAccessDerivePartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessDerivePartTest001");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_deriveAccessFinish001,
        sizeof(g_deriveAccessFinish001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(CheckAccessDeriveTest(HKS_ACCESS_TEST_001_PARAMS, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAliasFinish001, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlDeriveTest.HksAccessDerivePartTest002
 * @tc.desc: alg-PBKDF2 gen-pur-Derive.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlDeriveTest, HksAccessDerivePartTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessDerivePartTest002");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_deriveAccessFinish002,
        sizeof(g_deriveAccessFinish002) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(CheckAccessDeriveTest(HKS_ACCESS_TEST_002_PARAMS, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAliasFinish002, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlDeriveTest.HksAccessDerivePartTest003
 * @tc.desc: supports fine-grained access control, alg-HKDF gen-pur-Derive.
 * @tc.type: FUNC
 * @tc.auth_type: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlDeriveTest, HksAccessDerivePartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessDerivePartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_deriveAccessFinish001,
        sizeof(g_deriveAccessFinish001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE }
    );
    ASSERT_EQ(CheckAccessDeriveTest(testAccessCaseParams, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAliasFinish001, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlDeriveTest.HksAccessDerivePartTest004
 * @tc.desc: supports fine-grained access control, alg-PBKDF2 gen-pur-Derive.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlDeriveTest, HksAccessDerivePartTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessDerivePartTest004");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_deriveAccessFinish002,
        sizeof(g_deriveAccessFinish002) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_002_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE }
    );
    ASSERT_EQ(CheckAccessDeriveTest(testAccessCaseParams, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKeyForDe(&g_keyAliasFinish002, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlDeriveTest.HksAccessDerivePartTest005
 * @tc.desc: one stage api:HksDerive do not support operate user-auth-key
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlDeriveTest, HksAccessDerivePartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessDerivePartTest005");
    uint8_t alias[] = "testCheckAuthDerive";
    struct HksBlob keyAlias = { sizeof(alias), alias };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_ACCESS_TEST_001_PARAMS.genParams.data(),
        HKS_ACCESS_TEST_001_PARAMS.genParams.size());
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKeyForDe(&keyAlias, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    // test sign
    struct HksParam deriveParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DERIVE },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_DERIVE_KEY_SIZE, .uint32Param = DERIVE_KEY_SIZE_32 },
    };
    struct HksParamSet *deriveParamSet = nullptr;
    ret = InitParamSet(&deriveParamSet, deriveParams, sizeof(deriveParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t out[256] = {0};
    struct HksBlob outBlob = { sizeof(out), out };
    ret = HksDeriveKeyForDe(deriveParamSet, &keyAlias, &outBlob);
    (void)HksFreeParamSet(&deriveParamSet);
    (void)HksDeleteKeyForDe(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
}
