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

#include "hks_keynode_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_keynode.c"
#include "file_ex.h"
#include "hks_keynode.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksKeyNodeTest {
class HksKeyNodeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksKeyNodeTest::SetUpTestCase(void)
{
}

void HksKeyNodeTest::TearDownTestCase(void)
{
}

void HksKeyNodeTest::SetUp()
{
}

void HksKeyNodeTest::TearDown()
{
}

static const struct HksParam g_params[] = {
    {
        .tag = HKS_TAG_CRYPTO_CTX,
        .uint64Param = 0
    },
};

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest001
 * @tc.desc: tdd HksCreateKeyNode, expect keyNode == NULL
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest001");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksInitParamSet failed";
    ret = HksAddParams(paramSet, g_params, sizeof(g_params) / sizeof(g_params[0]));
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksAddParams failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksKeyNodeTest001 HksBuildParamSet failed";
    struct HuksKeyNode *keyNode = HksCreateKeyNode(nullptr, paramSet);
    EXPECT_EQ(keyNode == nullptr, true) << "HksKeyNodeTest001 HksCreateKeyNode not failed";
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest002
 * @tc.desc: tdd HksKeyNodeTest002, function is FreeKeyBlobParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest002");
    struct HksParamSet **param = nullptr;
    FreeKeyBlobParamSet(param);
    EXPECT_EQ(param == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest003
 * @tc.desc: tdd HksKeyNodeTest003, function is FreeParamsForBuildKeyNode
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest003");
    struct HksBlob blob = {
        .size = sizeof(HksBlob),
        .data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob))),
    };

    FreeParamsForBuildKeyNode(&blob, nullptr, nullptr, nullptr);

    struct HksParamSet *runtimeParamSet = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(runtimeParamSet == nullptr, false) << "runtimeParamSet malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, nullptr, nullptr);

    struct HksParamSet *keyBlobParamSet = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(keyBlobParamSet == nullptr, false) << "keyBlobParamSet malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, &keyBlobParamSet, nullptr);

    struct HuksKeyNode *keyNode = reinterpret_cast<HuksKeyNode *>(HksMalloc(sizeof(HuksKeyNode)));
    ASSERT_EQ(keyNode == nullptr, false) << "keyNode malloc failed.";
    FreeParamsForBuildKeyNode(&blob, &runtimeParamSet, &keyBlobParamSet, keyNode);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest004
 * @tc.desc: tdd HksKeyNodeTest004, function is FreeCachedData
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest004");
    void *ctx = nullptr;
    FreeCachedData(&ctx);

    struct HksBlob *blob = reinterpret_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    ASSERT_EQ(blob == nullptr, false) << "blob malloc failed.";
    blob->size = sizeof(HksBlob);
    blob->data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob)));
    FreeCachedData(reinterpret_cast<void **>(&blob));
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest005
 * @tc.desc: tdd HksKeyNodeTest005, function is KeyNodeFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest005");
    void *ctx = nullptr;
    KeyNodeFreeCtx(HKS_KEY_PURPOSE_AGREE, HKS_ALG_RSA, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_DERIVE, HKS_ALG_RSA, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_ENCRYPT, HKS_ALG_ECC, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_DECRYPT, HKS_ALG_ECC, false, &ctx);

    KeyNodeFreeCtx(HKS_KEY_PURPOSE_MAC, HKS_ALG_ECC, false, &ctx);
    EXPECT_EQ(ctx == nullptr, true);
}

/**
 * @tc.name: HksKeyNodeTest.HksKeyNodeTest006
 * @tc.desc: tdd HksKeyNodeTest006, function is FreeRuntimeParamSet
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyNodeTest, HksKeyNodeTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyNodeTest006");
    struct HksParamSet **paramSet = nullptr;
    FreeRuntimeParamSet(paramSet);
    struct HksParamSet *paramSetTwo = reinterpret_cast<HksParamSet *>(HksMalloc(sizeof(HksParamSet)));
    ASSERT_EQ(paramSetTwo == nullptr, false) << "paramSetTwo malloc failed.";
    FreeRuntimeParamSet(&paramSetTwo);
}

}