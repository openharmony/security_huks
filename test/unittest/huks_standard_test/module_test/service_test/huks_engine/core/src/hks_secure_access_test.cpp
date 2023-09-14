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

#include "hks_secure_access_test.h"

#include <gtest/gtest.h>

#include "file_ex.h"
#include "hks_keynode.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#include "hks_secure_access.h"

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_secure_access.c"

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

static int32_t BuildParamSetWithParam(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCnt,
    bool isWithMandataryParams)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    if (isWithMandataryParams) {
        struct HksParam processNameBlob = {
            .tag = HKS_TAG_PROCESS_NAME,
            .blob = {
                .size = strlen("0"),
                .data = (uint8_t *)"0"
            }
        };
        ret = HksAddParams(*paramSet, &processNameBlob, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAddParams failed");
            return ret;
        }
    }

    if (params != nullptr) {
        ret = HksAddParams(*paramSet, params, paramCnt);
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
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob, 1, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };

    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime, 1, true);
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
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob, 1, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };
    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime, 1, true);
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
    int32_t ret = BuildParamSetWithParam(&blobParamSet, nullptr, 0, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam accessTokenIdRuntime = { .tag = HKS_TAG_ACCESS_TOKEN_ID, .uint64Param = 0 };

    ret = BuildParamSetWithParam(&runtimeParamSet, &accessTokenIdRuntime, 1, true);
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
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &accessTokenIdBlob, 1, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;

    ret = BuildParamSetWithParam(&runtimeParamSet, nullptr, 0, true);
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

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest007
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest007");

    struct HksParamSet *blobParamSet = nullptr;
    int32_t ret = BuildParamSetWithParam(&blobParamSet, nullptr, 0, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksBlob wrongKeyAlias = { .size = strlen("0"), .data = (uint8_t *)"0"};
    struct HksParam keyAliasRuntime = { .tag = HKS_TAG_KEY_ALIAS, .blob = wrongKeyAlias};
    ret = BuildParamSetWithParam(&runtimeParamSet, &keyAliasRuntime, 1, true);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest008
 * @tc.desc: tdd HksProcessIdentityVerify, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest008");

    struct HksParamSet *blobParamSet = nullptr;
    int32_t ret = BuildParamSetWithParam(&blobParamSet, nullptr, 0, true);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksParam userIdRuntime = { .tag = HKS_TAG_USER_ID, .uint32Param = 1 };
    ret = BuildParamSetWithParam(&runtimeParamSet, &userIdRuntime, 1, true);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksProcessIdentityVerify(blobParamSet, runtimeParamSet);
    EXPECT_EQ(ret, HKS_SUCCESS);
    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest009
 * @tc.desc: tdd HksCheckCompareProcessName, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest009");

    int32_t ret = HksCheckCompareProcessName(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest010
 * @tc.desc: tdd HksCheckCompareProcessName, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest010");
    struct HksParamSet *blobParamSet = nullptr;
    struct HksBlob processName = { .size = strlen("011"), .data = (uint8_t *)"011"};
    struct HksParam processNameBlob = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName};
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &processNameBlob, 1, false);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksCheckCompareProcessName(blobParamSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);
    HksFreeParamSet(&blobParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest011
 * @tc.desc: tdd HksCheckCompareProcessName, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest011");
    struct HksParamSet *blobParamSet = nullptr;
    struct HksBlob processName = { .size = strlen("011"), .data = (uint8_t *)"011"};
    struct HksParam processNameBlob = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName};
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &processNameBlob, 1, false);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksBlob processName2 = { .size = strlen("012"), .data = (uint8_t *)"012"};
    struct HksParam processNameRuntime = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName2};
    ret = BuildParamSetWithParam(&runtimeParamSet, &processNameRuntime, 1, false);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksCheckCompareProcessName(blobParamSet, runtimeParamSet);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);

    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest012
 * @tc.desc: tdd HksCheckCompareProcessName, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest012");
    struct HksParamSet *blobParamSet = nullptr;
    struct HksBlob processName = { .size = strlen("011"), .data = (uint8_t *)"011"};
    struct HksParam processNameBlob = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName};
    int32_t ret = BuildParamSetWithParam(&blobParamSet, &processNameBlob, 1, false);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *runtimeParamSet = nullptr;
    struct HksBlob processName2 = { .size = strlen("0121"), .data = (uint8_t *)"0121"};
    struct HksParam processNameRuntime = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName2};
    ret = BuildParamSetWithParam(&runtimeParamSet, &processNameRuntime, 1, false);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksCheckCompareProcessName(blobParamSet, runtimeParamSet);
    ASSERT_EQ(ret, HKS_ERROR_BAD_STATE);

    HksFreeParamSet(&blobParamSet);
    HksFreeParamSet(&runtimeParamSet);
}

/**
 * @tc.name: HksSecureAccessTest.HksSecureAccessTest013
 * @tc.desc: tdd HksCoreSecureAccessInitParams, need user auth access control
 * @tc.type: FUNC
 */
HWTEST_F(HksSecureAccessTest, HksSecureAccessTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksSecureAccessTest013");
    struct HksParam parmas[] = {
        {
            .tag = HKS_TAG_USER_AUTH_TYPE,
            .uint32Param = HKS_USER_AUTH_TYPE_FINGERPRINT
        },
        {
            .tag = HKS_TAG_KEY_AUTH_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_PURPOSE,
            .uint32Param = HKS_KEY_PURPOSE_DECRYPT
        }, {
            .tag = HKS_TAG_ALGORITHM,
            .uint32Param = HKS_ALG_SM4
        }, {
            .tag = HKS_TAG_BLOCK_MODE,
            .uint32Param = HKS_MODE_CBC
        }
    };
    struct HksBlob token = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSecureAccessTest013 HksInitParamSet failed";
    ret = HksAddParams(paramSet, parmas, sizeof(parmas) / sizeof(parmas[0]));
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSecureAccessTest013 HksAddParams failed";
    ret = HksBuildParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksSecureAccessTest013 HksBuildParamSet failed";
    struct HuksKeyNode keyNode = { { nullptr, nullptr }, paramSet, nullptr, nullptr, 0 };
    ret = HksCoreSecureAccessInitParams(&keyNode, paramSet, &token);
    EXPECT_EQ(ret, HKS_ERROR_PARAM_NOT_EXIST);
    HksFreeParamSet(&paramSet);
}
}
