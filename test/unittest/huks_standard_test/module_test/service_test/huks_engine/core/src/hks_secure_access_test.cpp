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

#include "hks_secure_access_test.h"

#include <gtest/gtest.h>

#include "hks_keynode.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#include "hks_secure_access.h"

using namespace testing::ext;
namespace Unittest::HksSecureAccessTest {
class HksSecureAccessTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSecureAccessTest::SetUpTestCase(void)
{
}

void HksSecureAccessTest::TearDownTestCase(void)
{
}

void HksSecureAccessTest::SetUp()
{
}

void HksSecureAccessTest::TearDown()
{
}

static int32_t BuildParamSetWithParam(struct HksParamSet **paramSet, struct HksParam *param)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    if (param != nullptr) {
        ret = HksAddParams(*paramSet, param, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAddParams failed");
            return ret;
        }
    }

    return HksBuildParamSet(paramSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest001
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest001");

    struct HksParamSet *blobParamSet = nullptr;
    struct HksParam accessTokenIdBlob = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };

    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest002
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest002");

    struct HksParamSet *blobParamSet = nullptr;
    struct HksParam accessTokenIdBlob = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 1 };
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };
    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_ERROR_BAD_STATE);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest003
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest003");

    struct HksParamSet *blobParamSet = nullptr;
    int32_t ret = BuildParamSetWithParam(&blobParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };

    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest004
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest004");

    struct HksParamSet *blobParamSet = nullptr;
    struct HksParam accessTokenIdBlob = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 1 };
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;

    ret = BuildParamSetWithParam(&runtimeParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_ERROR_BAD_STATE);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest005
 * @tc.desc: tdd HksCoreSecureAccessInitParams, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest005");
    int32_t ret = HksCoreSecureAccessInitParams(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest006
 * @tc.desc: tdd HksCoreSecureAccessVerifyParams, expect HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest006");
    int32_t ret = HksCoreSecureAccessVerifyParams(nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}
}
