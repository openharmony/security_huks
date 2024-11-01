/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "hks_safe_compare_key_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_file_operator.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_file_operator.h"
#include "hks_test_log.h"
#include "hks_test_mem.h"

using namespace testing::ext;
namespace {
class HksSafeCompareKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSafeCompareKeyTest::SetUpTestCase(void)
{
}

void HksSafeCompareKeyTest::TearDownTestCase(void)
{
}

void HksSafeCompareKeyTest::SetUp()
{
}

void HksSafeCompareKeyTest::TearDown()
{
}

const char *g_storePath = HKS_KEY_STORE_PATH "/+0+0+0+0/key";
const char *g_testOne = "TestOne";
const char *g_testTwo = "TestTwo";

static const struct HksTestGenKeyParams g_testGenKeyParams[] = {
    /* x25519: tee sign/verify */
    { 0, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true,
            true, HKS_ALG_X25519,
            true, HKS_CURVE25519_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
            false, 0,
            false, 0,
            false,
            0,
            false, 0
        },
        { false, 0 },
    },
};

static int32_t SafeTestGenerateKey(struct HksBlob *keyAlias)
{
    uint32_t index = 0;

    struct HksParamSet *paramSet = NULL;
    struct GenerateKeyParamSetStructure paramStruct = {
        &paramSet,
        g_testGenKeyParams[index].paramSetParams.paramSetExist, g_testGenKeyParams[index].paramSetParams.setAlg,
        g_testGenKeyParams[index].paramSetParams.alg, g_testGenKeyParams[index].paramSetParams.setKeySize,
        g_testGenKeyParams[index].paramSetParams.keySize,
        g_testGenKeyParams[index].paramSetParams.setPurpose, g_testGenKeyParams[index].paramSetParams.purpose,
        g_testGenKeyParams[index].paramSetParams.setDigest, g_testGenKeyParams[index].paramSetParams.digest,
        g_testGenKeyParams[index].paramSetParams.setPadding, g_testGenKeyParams[index].paramSetParams.padding,
        g_testGenKeyParams[index].paramSetParams.setBlockMode, g_testGenKeyParams[index].paramSetParams.mode,
        g_testGenKeyParams[index].paramSetParams.setKeyStorageFlag,
        g_testGenKeyParams[index].paramSetParams.keyStorageFlag
    };
    int32_t ret = TestConstructGenerateKeyParamSet(&paramStruct);
    EXPECT_TRUE(ret == 0);

    uint32_t performTimes = 1;
    struct HksParamSet *paramSetOut = NULL;
    ret = TestConstructGenerateKeyParamSetOut(&paramSetOut,
        g_testGenKeyParams[index].paramSetParamsOut.paramSetExist,
        g_testGenKeyParams[index].paramSetParamsOut.paramSetSize);
    EXPECT_TRUE(ret == 0);

    ret = HksGenerateKeyRun(keyAlias, paramSet, paramSetOut, performTimes);
    if (ret != g_testGenKeyParams[index].expectResult) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", g_testGenKeyParams[index].testId, ret);
    }
    EXPECT_TRUE(ret == g_testGenKeyParams[index].expectResult);
    ret = 1;
    if (ret == g_testGenKeyParams[index].expectResult) {
        ret = 0;
    }
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&paramSetOut);
    return ret;
}

static int32_t CompareKeyData(struct HksBlob *keyAliasOne, struct HksBlob *keyAliasTwo)
{
    uint32_t sizeOne = HksFileSize(g_storePath, (char *)keyAliasOne->data);
    uint8_t *bufOne = (uint8_t *)HksTestMalloc(sizeOne);
    if (bufOne == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob blobOne = { .size = sizeOne, .data = bufOne };
    [[maybe_unused]] uint32_t sizeRead = 0;
    int32_t ret = HksFileRead(g_storePath, (char *)keyAliasOne->data, 0, &blobOne, &sizeRead);

    uint32_t sizeTwo = HksFileSize(g_storePath, (char *)keyAliasTwo->data);
    uint8_t *bufTwo = (uint8_t *)HksTestMalloc(sizeTwo);
    if (bufTwo == nullptr) {
        HksTestFree(bufOne);
        return HKS_ERROR_MALLOC_FAIL;
    }
    struct HksBlob blobTwo = { .size = sizeOne, .data = bufTwo };
    ret = HksFileRead(g_storePath, (char *)keyAliasTwo->data, 0, &blobTwo, &sizeRead);
    ret = memcmp(bufOne, bufTwo, sizeOne);
    HksTestFree(bufOne);
    HksTestFree(bufTwo);
    return ret;
}

/**
 * @tc.name: HksSafeCompareKeyTest.HksSafeCompareKeyTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksSafeCompareKeyTest, HksSafeCompareKeyTest001, TestSize.Level0)
{
    struct HksBlob keyAliasOne = { strlen(g_testOne), (uint8_t *)g_testOne };
    int32_t ret = SafeTestGenerateKey(&keyAliasOne);
    HKS_TEST_ASSERT(ret == 0);
    struct HksBlob keyAliasTwo = { strlen(g_testTwo), (uint8_t *)g_testTwo };
    ret = SafeTestGenerateKey(&keyAliasTwo);
    HKS_TEST_ASSERT(ret == 0);

    ret = CompareKeyData(&keyAliasOne, &keyAliasTwo);
    HKS_TEST_ASSERT(ret != 0);
    ASSERT_TRUE(ret != 0);
    (void)HksDeleteKeyForDe(&keyAliasOne, nullptr);
    (void)HksDeleteKeyForDe(&keyAliasTwo, nullptr);
}
}
