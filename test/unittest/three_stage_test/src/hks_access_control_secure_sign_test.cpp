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

#include <gtest/gtest.h>

#include "hks_import_wrapped_test_common.h"
#include "hks_three_stage_test_common.h"
#include "hks_access_control_test_common.h"
#include "hks_mem.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_api.h"
#include "hks_access_control_secure_sign_test.h"

using namespace testing::ext;
using namespace Unittest::HksAccessControlPartTest;
namespace Unittest::AccessControlSecureSignTest {
class HksAccessControlSecureSignTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlSecureSignTest::SetUpTestCase(void)
{
}

void HksAccessControlSecureSignTest::TearDownTestCase(void)
{
}

void HksAccessControlSecureSignTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksAccessControlSecureSignTest::TearDown()
{
}

static struct HksBlob g_genKeyAlias = {
    .size = strlen("TestGenKeyForSignWithInfo"),
    .data = (uint8_t *)"TestGenKeyForSignWithInfo"
};

struct HksTestSecureSignGenParams {
    struct HksBlob *keyAlias;
    struct HksParam *inputParams;
    uint32_t inputParamSize;
    int32_t expectResult;
};

static struct HksParam g_genRsaWithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_RSA
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = HKS_RSA_KEY_SIZE_4096
}, {
    .tag = HKS_TAG_PADDING,
    .uint32Param = HKS_PADDING_PSS
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA512
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_PIN
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};

static struct HksParam g_genEd25519WithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_ED25519
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = HKS_CURVE25519_KEY_SIZE_256
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA1
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_FACE
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};

static struct HksParam g_genDsaWithSignAuthParams[] = {
{
    .tag = HKS_TAG_ALGORITHM,
    .uint32Param = HKS_ALG_DSA
}, {
    .tag = HKS_TAG_PURPOSE,
    .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY
}, {
    .tag = HKS_TAG_KEY_SIZE,
    .uint32Param = 1024
}, {
    .tag = HKS_TAG_DIGEST,
    .uint32Param = HKS_DIGEST_SHA1
}, {
    .tag = HKS_TAG_USER_AUTH_TYPE,
    .uint32Param = HKS_USER_AUTH_TYPE_PIN
}, {
    .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE,
    .uint32Param = HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD
}, {
    .tag = HKS_TAG_CHALLENGE_TYPE,
    .uint32Param = HKS_CHALLENGE_TYPE_NORMAL
}, {
    .tag = HKS_TAG_KEY_SECURE_SIGN_TYPE,
    .uint32Param = HKS_SECURE_SIGN_WITH_AUTHINFO
}
};

static struct HksTestSecureSignGenParams g_testRsaGenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genRsaWithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genRsaWithSignAuthParams),
    .expectResult = HKS_SUCCESS
};

static struct HksTestSecureSignGenParams g_testEd25519GenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genEd25519WithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genEd25519WithSignAuthParams),
    .expectResult = HKS_SUCCESS
};

static struct HksTestSecureSignGenParams g_testDsaGenParams = {
    .keyAlias = &g_genKeyAlias,
    .inputParams = g_genDsaWithSignAuthParams,
    .inputParamSize = HKS_ARRAY_SIZE(g_genDsaWithSignAuthParams),
    .expectResult = HKS_SUCCESS
};

static int32_t CheckSignWithInfoTag(const struct HksBlob *alias, const struct HksParamSet *paramSet)
{
    struct HksParamSet *keyParamSet = NULL;
    int32_t ret = GenParamSetAuthTest(&keyParamSet, paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "GenParamSetAuthTest failed.";

    ret = HksGetKeyParamSet(alias, paramSet, keyParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetKeyParamSet failed.";

    struct HksParam *secureParam = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &secureParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam auth access failed.";

    struct HksParam *userParam = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_USER_AUTH_TYPE, &userParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam user auth failed.";

    struct HksParam *secSignType = nullptr;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SECURE_SIGN_TYPE, &secSignType);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGetParam secure sign type failed.";
    EXPECT_EQ(secSignType->uint32Param, HKS_SECURE_SIGN_WITH_AUTHINFO) << "HksGetParam secure sign type failed.";

    HksFreeParamSet(&keyParamSet);
    return ret;
}

static void TestGenerateKeyWithSecureSignTag(struct HksTestSecureSignGenParams *params)
{
    struct HksParamSet *genParamSet = NULL;
    int32_t ret = InitParamSet(&genParamSet, params->inputParams, params->inputParamSize);
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    /**
     * @tc.steps:step1. Generate a key with user_auth_type and sign_with_info tag
     */
    ret = HksGenerateKey(params->keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey rsa key failed.";

    /**
     * @tc.steps:step2. Get key paramSet check if related key tag exist
     */
    ret = CheckSignWithInfoTag(params->keyAlias, genParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "CheckSignWithInfoTag rsa key failed.";

    /**
     * @tc.steps:step3. Delete key and free paramSet
     */
    HksDeleteKey(params->keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksAccessControlSecureSignTest001
 * @tc.desc: normal case to test generate a rsa key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest001, TestSize.Level0)
{
    TestGenerateKeyWithSecureSignTag(&g_testRsaGenParams);
}

/**
 * @tc.name: HksAccessControlSecureSignTest002
 * @tc.desc: normal case to test generate a ed25519 key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest002, TestSize.Level0)
{
    TestGenerateKeyWithSecureSignTag(&g_testEd25519GenParams);
}

/**
 * @tc.name: HksAccessControlSecureSignTest003
 * @tc.desc: normal case to test generate a dsa key with sign_with_info tag and check paramSet
 *           has the tag
 * @tc.type: FUNC
 */
HWTEST_F(HksAccessControlSecureSignTest, HksAccessControlSecureSignTest003, TestSize.Level0)
{
#ifdef _USE_OPENSSL_
    TestGenerateKeyWithSecureSignTag(&g_testDsaGenParams);
#endif
}
}