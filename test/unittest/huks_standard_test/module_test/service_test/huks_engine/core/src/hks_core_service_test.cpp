/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "hks_client_ipc.h"
#include "hks_core_service_test.h"

#include <gtest/gtest.h>
#include <string>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include "hks_client_service.h"
#include "hks_storage_manager.h"

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_core_service.c"

using namespace testing::ext;
namespace Unittest::HksCoreServiceTest {
class HksCoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCoreServiceTest::SetUpTestCase(void)
{
    static_cast<void>(HksClientInitialize());
}

void HksCoreServiceTest::TearDownTestCase(void)
{
}

void HksCoreServiceTest::SetUp()
{
}

void HksCoreServiceTest::TearDown()
{
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest001
 * @tc.desc: tdd HksCoreAbort, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest001");
    int32_t ret = HksCoreAbort(nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest002
 * @tc.desc: tdd HksCoreAbort, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest002");
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCoreAbort(&handle, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest003
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest003");
    int32_t ret = HksCoreFinish(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest004
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest004");
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreFinish(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest005
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest005");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint64_t), .data = (uint8_t *)&handleData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreFinish(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_BAD_STATE);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest006
 * @tc.desc: tdd HksCoreUpdate, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest006");
    int32_t ret = HksCoreUpdate(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest007
 * @tc.desc: tdd HksCoreUpdate, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest007");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = (uint8_t *)&handleData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreUpdate(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest008
 * @tc.desc: tdd HksCoreInit, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest008");
    int32_t ret = HksCoreInit(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest009
 * @tc.desc: tdd HksCoreInit, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest009");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint32_t), .data = (uint8_t *)&handleData };
    struct HksBlob token = { 0 };
    struct HksBlob key = { 0 };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCoreInit(&key, paramSet, &handle, &token);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

static int32_t TestGenerateKey(const struct HksBlob *keyAlias, const struct HksProcessInfo *processInfo)
{
    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksAddParams failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksBuildParamSet failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksServiceGenerateKey(processInfo, keyAlias, paramSet, nullptr);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("hks_core_service_test HksGenerateKey failed");
    }
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t BuildParamSetWithParam(struct HksParamSet **paramSet, struct HksParam *param)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("BuildParamSetWithParam HksInitParamSet failed");
        return ret;
    }
    if (param != nullptr) {
        ret = HksAddParams(*paramSet, param, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("BuildParamSetWithParam HksAddParams failed");
            return ret;
        }
    }
    return HksBuildParamSet(paramSet);
}

static const char *g_processNameString = "hks_client";
static const struct HksBlob g_processName = { strlen(g_processNameString), (uint8_t *)g_processNameString };
static const uint32_t USER_ID_INT = 0;
static const struct HksBlob g_userId = { sizeof(USER_ID_INT), (uint8_t *)(&USER_ID_INT)};
static const uint32_t KEY_BLOB_DEFAULT_SIZE = 4096;

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest010
 * @tc.desc: tdd HksCoreExportPublicKey with wrong access token id, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest010");
    const char *alias = "HksCoreServiceTest010";
    const struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksProcessInfo processInfo = { g_userId, g_processName, USER_ID_INT, 0, 0 };
    int32_t ret = TestGenerateKey(&keyAlias, &processInfo);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksBlob keyBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };
    ASSERT_NE(keyBlob.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksManageStoreGetKeyBlob(&processInfo, paramSet, &keyAlias, &keyBlob, HKS_STORAGE_TYPE_KEY);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 1 };
    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksBlob keyOutBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };

    ret = HksCoreExportPublicKey(&keyBlob, runtimeParamSet, &keyOutBlob);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);

    (void)HksServiceDeleteKey(&processInfo, &keyAlias, nullptr);
    HKS_FREE(keyOutBlob.data);
    HKS_FREE(keyBlob.data);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest011
 * @tc.desc: tdd CheckAgreeKeyIn with key, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest011");
    const uint32_t keySize = 1;
    uint8_t keyData[keySize] = { 0 };
    struct HksBlob key = { .size = keySize, .data = keyData };
    int32_t ret = CheckAgreeKeyIn(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest012
 * @tc.desc: tdd CheckAgreeKeyIn with key, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest012");
    const uint32_t tooBigger = 9999;
    struct Hks25519KeyPair keyPair = { .publicBufferSize = 0, .privateBufferSize = tooBigger };
    struct HksBlob key = { .size = sizeof(keyPair), .data = (uint8_t *)&keyPair };
    int32_t ret = CheckAgreeKeyIn(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest013
 * @tc.desc: tdd CheckAgreeKeyIn with key, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest013");
    const uint32_t tooBigger = 9999;
    struct Hks25519KeyPair keyPair = { .publicBufferSize = tooBigger, .privateBufferSize = 0 };
    struct HksBlob key = { .size = sizeof(keyPair), .data = (uint8_t *)&keyPair };
    int32_t ret = CheckAgreeKeyIn(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest014
 * @tc.desc: tdd HksCoreExportPublicKey with null input, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest014");
    struct HksBlob keyBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };
    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 1 };
    int32_t ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksBlob keyOutBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };
    ret = HksCoreExportPublicKey(&keyBlob, runtimeParamSet, nullptr);
    ret = HksCoreExportPublicKey(nullptr, runtimeParamSet, &keyOutBlob);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
    HKS_FREE(keyOutBlob.data);
    HKS_FREE(keyBlob.data);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest015
 * @tc.desc: GetPrivateOrPairInnerFormat with different algParams, for condition test, do not expect any results.
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest015, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest015");
    const uint32_t tooBigger = 9999;
    struct Hks25519KeyPair keyPair = { .publicBufferSize = tooBigger, .privateBufferSize = 0 };
    struct HksBlob key = { .size = sizeof(keyPair), .data = (uint8_t *)&keyPair };

    struct HksParam algParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DSA},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_DH},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM3},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM4},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ED25519},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_X25519},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = 0},
    };
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(algParams) / sizeof(algParams[0])); ++i) {
        struct HksParamSet *runtimeParamSet = nullptr;
        int32_t ret = BuildParamSetWithParam(&runtimeParamSet, &algParams[i]);
        ASSERT_EQ(ret, HKS_SUCCESS);
        struct HksBlob innerKey = { 0, nullptr };
        (void)GetPrivateOrPairInnerFormat(HKS_KEY_TYPE_PRIVATE_KEY, &key, runtimeParamSet, &innerKey);
        HksFreeParamSet(&runtimeParamSet);
        HKS_FREE_BLOB(innerKey);
    }
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest016
 * @tc.desc: tdd HksCoreExportPublicKey with wrong user id, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest016, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest016");
    const char *alias = "HksCoreServiceTest016";
    const struct HksBlob keyAlias = { strlen(alias), (uint8_t *)alias };
    struct HksProcessInfo processInfo = { g_userId, g_processName, USER_ID_INT, 0, 0 };
    int32_t ret = TestGenerateKey(&keyAlias, &processInfo);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksCoreServiceTest016 ret is " << ret;
    struct HksBlob keyBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };
    ASSERT_NE(keyBlob.data, nullptr);

    struct HksParamSet *paramSet = nullptr;
    struct HksParam storageLevel = { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE };
    ret = BuildParamSetWithParam(&paramSet, &storageLevel);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksManageStoreGetKeyBlob(&processInfo, paramSet, &keyAlias, &keyBlob, HKS_STORAGE_TYPE_KEY);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam userIdRuntime = { .tag = HKS_TAG_USER_ID, .uint32Param = 1 };
    ret = BuildParamSetWithParam(&runtimeParamSet, &userIdRuntime);
    ASSERT_EQ(ret, HKS_SUCCESS);
    struct HksBlob keyOutBlob = { .size = KEY_BLOB_DEFAULT_SIZE, .data = (uint8_t *)HksMalloc(KEY_BLOB_DEFAULT_SIZE) };

    ret = HksCoreExportPublicKey(&keyBlob, runtimeParamSet, &keyOutBlob);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);

    HKS_FREE(keyOutBlob.data);
    HKS_FREE(keyBlob.data);
    HksFreeParamSet(&runtimeParamSet);
    (void)HksServiceDeleteKey(&processInfo, &keyAlias, nullptr);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest017
 * @tc.desc: test HksCoreAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest017, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest017");
    // invalid certchain size
    uint8_t buffer[HKS_ATTEST_CERT_SIZE - 1] = {0};
    struct HksBlob blob = { HKS_ATTEST_CERT_SIZE - 1, buffer };
    int32_t ret = HksCoreAttestKey(&blob, nullptr, &blob);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksCoreAttestKey success" << ret;
}

/**
 * @tc.name: HksCoreServiceTest.HksKeyAttest002
 * @tc.desc: test HksCoreAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest018, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest018");
    int32_t ret = HksCoreAttestKey(nullptr, nullptr, nullptr);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksCoreAttestKey success" << ret;
}

/**
 * @tc.name: HksCoreServiceTest.HksKeyAttest003
 * @tc.desc: test HksCoreAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest019, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest019");
    // invalid paramSet
    uint8_t buffer[HKS_ATTEST_CERT_SIZE] = {0};
    struct HksBlob blob = {HKS_ATTEST_CERT_SIZE, buffer};
    int32_t ret = HksCoreAttestKey(&blob, nullptr, &blob);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksCoreAttestKey not null pointer" << ret;
}
}
