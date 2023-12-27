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

#include "hks_access_control_agree_test.h"
#include "hks_access_control_test_common.h"
#include "hks_api.h"
#include "hks_struct_macro_def.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
class HksAccessControlAgreeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlAgreeTest::SetUpTestCase(void)
{
}

void HksAccessControlAgreeTest::TearDownTestCase(void)
{
}

void HksAccessControlAgreeTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlAgreeTest::TearDown()
{
}

/* 001: gen ecdh for agree; init for agree */
const TestAccessCaseParams HKS_ACCESS_TEST_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};
static struct HksBlob g_keyAliasFinal001 = {
    strlen("HksECDHAgreeKeyAliasTest001_final"),
    (uint8_t *)"HksECDHAgreeKeyAliasTest001_final"
};

static struct HksParam g_agreeAccessFinish001[] = {
    HKS_DERIVE_FINISH_AES_256_COMMON
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal001
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

/* 002: gen x25519 for agree; init for agree */
static struct TestAccessCaseParams HKS_ACCESS_TEST_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519 },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FACE },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};
static struct HksBlob g_keyAliasFinal002 = {
    strlen("HksX25519AgreeKeyAliasTest002_final"),
    (uint8_t *)"HksX25519AgreeKeyAliasTest002_final"
};
static struct HksParam g_agreeAccessFinish002[] = {
    HKS_DERIVE_FINISH_AES_256_COMMON
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal002
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

/* 003: gen dh for agree; init for agree */
static struct TestAccessCaseParams HKS_ACCESS_TEST_003_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_DH_KEY_SIZE_2048 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
        },
    .initResult = HKS_SUCCESS
};
static struct HksBlob g_keyAliasFinal003 = {
    strlen("HksDHAgreeKeyAliasTest003_final"),
    (uint8_t *)"HksDHAgreeKeyAliasTest003_final"
};
static struct HksParam g_agreeAccessFinish003[] = {
    HKS_DERIVE_FINISH_AES_256_COMMON
    {
        .tag = HKS_TAG_KEY_ALIAS,
        .blob = g_keyAliasFinal003
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest001
 * @tc.desc: alg-ECDH gen-pur-Agree.
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest001");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish001,
        sizeof(g_agreeAccessFinish001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(CheckAccessAgreeTest(HKS_ACCESS_TEST_001_PARAMS, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal001, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest002
 * @tc.desc: alg-X25519 gen-pur-Agree.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest002, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest002");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish002,
        sizeof(g_agreeAccessFinish002) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(CheckAccessAgreeTest(HKS_ACCESS_TEST_002_PARAMS, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal002, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest003
 * @tc.desc: alg-DH gen-pur-Agree.
 * @tc.type: FUNC
 * @tc.auth_type: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest003, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest003");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish003,
        sizeof(g_agreeAccessFinish003) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ASSERT_EQ(CheckAccessAgreeTest(HKS_ACCESS_TEST_003_PARAMS, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal003, nullptr), HKS_SUCCESS);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest004
 * @tc.desc: supports fine-grained access control, alg-ECDH gen-pur-Agree
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest004, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest004");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 1,
        .time = 0,
        .authType = 1
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish001,
        sizeof(g_agreeAccessFinish001) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_001_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE }
    );
    ASSERT_EQ(CheckAccessAgreeTest(testAccessCaseParams, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal001, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest005
 * @tc.desc: supports fine-grained access control, alg-X25519 gen-pur-Agree.
 * @tc.type: FUNC
 * @tc.auth_type: FACE
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest005, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest005");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 3,
        .time = 0,
        .authType = 2
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish002,
        sizeof(g_agreeAccessFinish002) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_002_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE }
    );
    ASSERT_EQ(CheckAccessAgreeTest(testAccessCaseParams, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal002, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest006
 * @tc.desc: supports fine-grained access control, alg-DH gen-pur-Agree.
 * @tc.type: FUNC
 * @tc.auth_type: FINGERPRINT
 * @tc.result:HKS_SUCCESS
 * @tc.require: issueI6UFG5
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest006, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest006");
    const IDMParams testIDMParams = {
        .secureUid = 1,
        .enrolledId = 2,
        .time = 0,
        .authType = 4
    };
    struct HksParamSet *finishParamSet = nullptr;
    int ret = InitParamSet(&finishParamSet, g_agreeAccessFinish003,
        sizeof(g_agreeAccessFinish003) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct TestAccessCaseParams testAccessCaseParams(HKS_ACCESS_TEST_003_PARAMS);
    testAccessCaseParams.genParams.push_back(
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE }
    );
    ASSERT_EQ(CheckAccessAgreeTest(testAccessCaseParams, finishParamSet,
        testIDMParams), HKS_SUCCESS);
    ASSERT_EQ(HksDeleteKey(&g_keyAliasFinal003, nullptr), HKS_SUCCESS);
    HksFreeParamSet(&finishParamSet);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest007
 * @tc.desc: alg-ECDH gen-pur-Agree one stage api
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest007, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest007");
    uint8_t alias[] = "testCheckAuthAgree";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    uint8_t alias2[] = "testCheckAuthAgree2";
    struct HksBlob keyAlias2 = { sizeof(alias2), alias2 };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_ACCESS_TEST_001_PARAMS.genParams.data(),
        HKS_ACCESS_TEST_001_PARAMS.genParams.size());
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    ret = HksGenerateKey(&keyAlias2, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParam agreeParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECDH },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    };
    struct HksParamSet *agreeParamSet = nullptr;
    ret = InitParamSet(&agreeParamSet, agreeParams, sizeof(agreeParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t eccPubData256[256] = {0};
    struct HksBlob publicKey = { sizeof(eccPubData256), eccPubData256 };
    ret = HksExportPublicKey(&keyAlias2, nullptr, &publicKey);
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t outData[256] = {0};
    struct HksBlob outDataBlob = { sizeof(outData), outData };
    ret = HksAgreeKey(agreeParamSet, &keyAlias, &publicKey, &outDataBlob);
    (void)HksFreeParamSet(&agreeParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);
    (void)HksDeleteKey(&keyAlias2, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}

/**
 * @tc.name: HksAccessControlAgreeTest.HksAccessAgreePartTest008
 * @tc.desc: one stage api:HksGenerateKet do not support operate user-auth-key
 * @tc.type: FUNC
 * @tc.auth_type: PIN
 * @tc.result:HKS_ERROR_NOT_SUPPORTED
 * @tc.require: issueI5NY0M
 */
HWTEST_F(HksAccessControlAgreeTest, HksAccessAgreePartTest008, TestSize.Level0)
{
    HKS_LOG_I("Enter HksAccessAgreePartTest008");
    uint8_t alias[] = "testCheckAuthAgree2";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    struct HksParam genX25519Params[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_AGREE},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256},
        { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = HKS_USER_AUTH_TYPE_PIN },
        { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD },
        { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = HKS_CHALLENGE_TYPE_NORMAL },
    };
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, genX25519Params, sizeof(genX25519Params) / sizeof(struct HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    (void)HksFreeParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t x25519PubData256[] = {
        0x9c, 0xf6, 0x7a, 0x8d, 0xce, 0xc2, 0x7f, 0xa7, 0xd9, 0xfd, 0xf1, 0xad, 0xac, 0xf0, 0xb3, 0x8c,
        0xe8, 0x16, 0xa2, 0x65, 0xcc, 0x18, 0x55, 0x60, 0xcd, 0x2f, 0xf5, 0xe5, 0x72, 0xc9, 0x3c, 0x54,
    };

    struct HksParam agreeParams[] =
    {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_AGREE },
        { .tag = HKS_TAG_AGREE_ALG, .uint32Param = HKS_ALG_X25519 },
        { .tag = HKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS, .boolParam = false },
        { .tag = HKS_TAG_AGREE_PRIVATE_KEY_ALIAS, .blob = keyAlias },
        { .tag = HKS_TAG_AGREE_PUBLIC_KEY, .blob = { .size = sizeof(x25519PubData256), .data = x25519PubData256} },
    };
    struct HksParamSet *agreeParamSet = nullptr;
    ret = InitParamSet(&agreeParamSet, agreeParams, sizeof(agreeParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    uint8_t agreeKeyAlias[] = "agree_abormal_key";
    struct HksBlob agreekeyAliasBlob = { sizeof(agreeKeyAlias), agreeKeyAlias };
    ret = HksGenerateKey(&agreekeyAliasBlob, agreeParamSet, nullptr);
    (void)HksFreeParamSet(&agreeParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED);
}
}