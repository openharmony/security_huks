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

#include "hks_param_test.h"

#include <gtest/gtest.h>

#include "hks_param.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

#include <string.h>

using namespace testing::ext;
namespace Unittest::HksFrameworkCommonCheckParamsetTest {
class HksParamTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksParamTest::SetUpTestCase(void)
{
}

void HksParamTest::TearDownTestCase(void)
{
}

void HksParamTest::SetUp()
{
}

void HksParamTest::TearDown()
{
}

/**
 * @tc.name: HksParamTest.HksParamTest001
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest001");
    struct HksParam baseParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA };
    struct HksParam otherParam = { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = HKS_CHALLENGE_POS_0 };
    int32_t ret = HksCheckParamMatch(&baseParam, &otherParam);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckParamMatch failed, ret = " << ret;
}

/**
 * @tc.name: HksParamTest.HksParamTest002
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest002");
    struct HksParam baseParam = { .tag = HKS_TAG_KEY_ACCESS_TIME, .uint64Param = (ulong)1 };
    struct HksParam otherParam = { .tag = HKS_TAG_KEY_ACCESS_TIME, .uint64Param = (ulong)2 };
    int32_t ret = HksCheckParamMatch(&baseParam, &otherParam);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckParamMatch failed, ret = " << ret;
}

/**
 * @tc.name: HksParamTest.HksParamTest003
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest003");
    struct HksParam baseParam = { .tag = HKS_TAG_IS_APPEND_UPDATE_DATA, .boolParam = true };
    struct HksParam otherParam = { .tag = HKS_TAG_IS_APPEND_UPDATE_DATA, .boolParam = false };
    int32_t ret = HksCheckParamMatch(&baseParam, &otherParam);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckParamMatch failed, ret = " << ret;
}

/**
 * @tc.name: HksParamTest.HksParamTest004
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest004");
    const char *baseData = "1";
    struct HksBlob baseBlob = { strlen(baseData), (uint8_t *)baseData};
    struct HksParam baseParam = { .tag = HKS_TAG_USER_AUTH_SECURE_UID, .blob = baseBlob};
    const char *otherData = "21";
    struct HksBlob otherBlob = { strlen(otherData), (uint8_t *)otherData};
    struct HksParam otherParam = { .tag = HKS_TAG_USER_AUTH_SECURE_UID, .blob = otherBlob };
    int32_t ret = HksCheckParamMatch(&baseParam, &otherParam);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckParamMatch failed, ret = " << ret;
}

/**
 * @tc.name: HksParamTest.HksParamTest005
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest005");
    const char *baseData = "1";
    struct HksBlob baseBlob = { strlen(baseData), (uint8_t *)baseData};
    struct HksParam baseParam = { .tag = HKS_TAG_USER_AUTH_SECURE_UID, .blob = baseBlob};
    const char *otherData = "2";
    struct HksBlob otherBlob = { strlen(otherData), (uint8_t *)otherData};
    struct HksParam otherParam = { .tag = HKS_TAG_USER_AUTH_SECURE_UID, .blob = otherBlob };
    int32_t ret = HksCheckParamMatch(&baseParam, &otherParam);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCheckParamMatch failed, ret = " << ret;
}

/**
 * @tc.name: HksParamTest.HksParamTest006
 * @tc.desc: tdd HksCheckParamMatch, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksParamTest, HksParamTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksParamTest006");
    const char *baseData = "1";
    struct HksBlob baseBlob = { strlen(baseData), (uint8_t *)baseData};
    struct HksParam baseParam = { .tag = HKS_TAG_USER_AUTH_SECURE_UID, .blob = baseBlob};
    int32_t ret = HksCheckParamMatch(&baseParam, &baseParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksCheckParamMatch failed, ret = " << ret;
}
}
