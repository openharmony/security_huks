/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_mlkem_service_test.h"

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_client_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksMlKemServiceTest {
class HksMlKemServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksMlKemServiceTest::SetUpTestCase(void)
{
}

void HksMlKemServiceTest::TearDownTestCase(void)
{
}

void HksMlKemServiceTest::SetUp()
{
}

void HksMlKemServiceTest::TearDown()
{
}

static const char *g_processNameString = "hks_mlkem_test";
static const struct HksBlob g_processName = { strlen(g_processNameString), (uint8_t *)g_processNameString };
static uint32_t g_userIdInt = 1;
static const struct HksBlob g_userId = { sizeof(g_userIdInt), (uint8_t *)(&g_userIdInt) };
static struct HksProcessInfo g_processInfo = { g_userId, g_processName, g_userIdInt, 0, 0 };

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest001
 * @tc.desc: tdd HksServiceEncapsulate, null keyAlias
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest001");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, nullptr, paramSet, sharedParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest002
 * @tc.desc: tdd HksServiceEncapsulate, null paramSet
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest002");
    const char *alias = "HksMlKemEncapsTest002";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, nullptr, sharedParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest003
 * @tc.desc: tdd HksServiceEncapsulate, key not exist
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest003");
    const char *alias = "HksMlKemEncapsNotExistTest003";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam sharedAliasParam = {
        .tag = HKS_TAG_KEY_ALIAS, .blob = { strlen("sharedKey003"), (uint8_t *)"sharedKey003" }
    };
    ret = HksAddParams(sharedParamSet, &sharedAliasParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest004
 * @tc.desc: tdd HksServiceEncapsulate, sharedKeyParamSet without KEY_ALIAS
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest004");
    const char *alias = "HksMlKemEncapsNoAliasTest004";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam sharedKeySizeParam = {
        .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_SHARED_SECRET_LEN
    };
    ret = HksAddParams(sharedParamSet, &sharedKeySizeParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapResult);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest005
 * @tc.desc: tdd HksServiceDecapsulate, null keyAlias
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest005");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t encapData[HKS_ML_KEM_MAX_CIPHERTEXT_LEN] = { 0 };
    struct HksBlob encapOrSharedSecret = { HKS_ML_KEM_MAX_CIPHERTEXT_LEN, encapData };
    ret = HksServiceDecapsulate(&g_processInfo, nullptr, paramSet, sharedParamSet, &encapOrSharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest006
 * @tc.desc: tdd HksServiceDecapsulate, null paramSet
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest006");
    const char *alias = "HksMlKemDecapsTest006";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *sharedParamSet = nullptr;
    int32_t ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t encapData[HKS_ML_KEM_MAX_CIPHERTEXT_LEN] = { 0 };
    struct HksBlob encapOrSharedSecret = { HKS_ML_KEM_MAX_CIPHERTEXT_LEN, encapData };
    ret = HksServiceDecapsulate(&g_processInfo, &keyAlias, nullptr, sharedParamSet, &encapOrSharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest007
 * @tc.desc: tdd HksServiceDecapsulate, key not exist
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest007");
    const char *alias = "HksMlKemDecapsNotExistTest007";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t encapData[HKS_ML_KEM_MAX_CIPHERTEXT_LEN] = { 0 };
    struct HksBlob encapOrSharedSecret = { HKS_ML_KEM_MAX_CIPHERTEXT_LEN, encapData };
    ret = HksServiceDecapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapOrSharedSecret);
    EXPECT_EQ(ret, HKS_ERROR_NOT_EXIST);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest008
 * @tc.desc: tdd HksServiceDecapsulate, sharedKeyParamSet without KEY_ALIAS
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest008");
    const char *alias = "HksMlKemDecapsNoAliasTest008";
    struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    };
    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam sharedKeySizeParam = {
        .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_SHARED_SECRET_LEN
    };
    ret = HksAddParams(sharedParamSet, &sharedKeySizeParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t encapData[HKS_ML_KEM_MAX_CIPHERTEXT_LEN] = { 0 };
    struct HksBlob encapOrSharedSecret = { HKS_ML_KEM_MAX_CIPHERTEXT_LEN, encapData };
    ret = HksServiceDecapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapOrSharedSecret);
    EXPECT_NE(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest009
 * @tc.desc: tdd HksServiceEncapsulate, sharedKeyParamSet without KEY_SIZE (skip storage)
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest009");
    const char *keyAliasStr = "HksMlKemEncapsNoSizeTest009";
    struct HksBlob keyAlias = { strlen(keyAliasStr), (uint8_t *)keyAliasStr };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksServiceGenerateKey(&g_processInfo, &keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return;
    }

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam opParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, opParams, sizeof(opParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam sharedAliasParam = {
        .tag = HKS_TAG_KEY_ALIAS, .blob = { strlen("sharedKey009"), (uint8_t *)"sharedKey009" }
    };
    ret = HksAddParams(sharedParamSet, &sharedAliasParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapResult);
    if (ret == HKS_SUCCESS) {
        EXPECT_NE(encapResult.encapsulatedData.data, nullptr);
        EXPECT_NE(encapResult.sharedSecret.data, nullptr);
        HKS_FREE(encapResult.encapsulatedData.data);
        HKS_FREE(encapResult.sharedSecret.data);
    }

    HksServiceDeleteKey(&g_processInfo, &keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest010
 * @tc.desc: tdd HksServiceEncapsulate, sharedKeyParamSet with KEY_SIZE (store and clear sharedSecret)
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest010");
    const char *keyAliasStr = "HksMlKemEncapsStoreTest010";
    struct HksBlob keyAlias = { strlen(keyAliasStr), (uint8_t *)keyAliasStr };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksServiceGenerateKey(&g_processInfo, &keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return;
    }

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam opParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, opParams, sizeof(opParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    const char *sharedAliasStr = "HksMlKemSharedKey010";
    struct HksParam sharedParams[] = {
        { .tag = HKS_TAG_KEY_ALIAS, .blob = { strlen(sharedAliasStr), (uint8_t *)sharedAliasStr } },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_SHARED_SECRET_LEN },
    };
    ret = HksAddParams(sharedParamSet, sharedParams, sizeof(sharedParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapResult);
    if (ret == HKS_SUCCESS) {
        EXPECT_NE(encapResult.encapsulatedData.data, nullptr);
        HKS_FREE(encapResult.encapsulatedData.data);
        struct HksBlob sharedKeyAliasBlob = { strlen(sharedAliasStr), (uint8_t *)sharedAliasStr };
        ret = HksServiceKeyExist(&g_processInfo, &sharedKeyAliasBlob, nullptr);
        EXPECT_EQ(ret, HKS_SUCCESS);
        HksServiceDeleteKey(&g_processInfo, &sharedKeyAliasBlob, nullptr);
    }

    HksServiceDeleteKey(&g_processInfo, &keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest011
 * @tc.desc: tdd HksServiceEncapsulate, purpose not include WRAP
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest011");
    const char *keyAliasStr = "HksMlKemEncapsNoWrapTest011";
    struct HksBlob keyAlias = { strlen(keyAliasStr), (uint8_t *)keyAliasStr };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    };
    ret = HksAddParams(genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksServiceGenerateKey(&g_processInfo, &keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return;
    }

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam opParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
    };
    ret = HksAddParams(paramSet, opParams, sizeof(opParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam sharedAliasParam = {
        .tag = HKS_TAG_KEY_ALIAS, .blob = { strlen("sharedKey011"), (uint8_t *)"sharedKey011" }
    };
    ret = HksAddParams(sharedParamSet, &sharedAliasParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksEncapsulationResult encapResult = { { 0, nullptr }, { 0, nullptr } };
    ret = HksServiceEncapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapResult);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);

    HksServiceDeleteKey(&g_processInfo, &keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}

/**
 * @tc.name: HksMlKemServiceTest.HksMlKemServiceTest012
 * @tc.desc: tdd HksServiceDecapsulate, purpose not include UNWRAP
 * @tc.type: FUNC
 */
HWTEST_F(HksMlKemServiceTest, HksMlKemServiceTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksMlKemServiceTest012");
    const char *keyAliasStr = "HksMlKemDecapsNoUnwrapTest012";
    struct HksBlob keyAlias = { strlen(keyAliasStr), (uint8_t *)keyAliasStr };

    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = HksInitParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
    };
    ret = HksAddParams(genParamSet, genParams, sizeof(genParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&genParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksServiceGenerateKey(&g_processInfo, &keyAlias, genParamSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return;
    }

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksParam opParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP },
    };
    ret = HksAddParams(paramSet, opParams, sizeof(opParams) / sizeof(HksParam));
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *sharedParamSet = nullptr;
    ret = HksInitParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&sharedParamSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t encapData[HKS_ML_KEM_MAX_CIPHERTEXT_LEN] = { 0 };
    struct HksBlob encapOrSharedSecret = { HKS_ML_KEM_MAX_CIPHERTEXT_LEN, encapData };
    ret = HksServiceDecapsulate(&g_processInfo, &keyAlias, paramSet, sharedParamSet, &encapOrSharedSecret);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_PURPOSE);

    HksServiceDeleteKey(&g_processInfo, &keyAlias, nullptr);
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedParamSet);
}
}