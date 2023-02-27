/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_upgrade_key_c_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_upgrade_key.c"

#include "hks_log.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksUpgradeKeyCTest {
class HksUpgradeKeyCTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUpgradeKeyCTest::SetUpTestCase(void)
{
}

void HksUpgradeKeyCTest::TearDownTestCase(void)
{
}

void HksUpgradeKeyCTest::SetUp()
{
}

void HksUpgradeKeyCTest::TearDown()
{
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest001
 * @tc.desc: tdd GetMandatoryParams, expect nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest001");
    struct HksMandatoryParams* ret = GetMandatoryParams(0);
    ASSERT_EQ(nullptr, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest002
 * @tc.desc: tdd GetMandatoryParams, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest002");
    uint32_t tooBigKeyVersion = 999;
    struct HksMandatoryParams* ret = GetMandatoryParams(tooBigKeyVersion);
    ASSERT_EQ(nullptr, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest003
 * @tc.desc: tdd IsTagInMandatoryArray, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest003");
    uint32_t tooBigKeyVersion = 999;
    bool ret = IsTagInMandatoryArray(HKS_TAG_ALGORITHM, tooBigKeyVersion);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest004
 * @tc.desc: tdd AddParamsWithoutMandatory, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest004");
    uint32_t tooBigKeyVersion = 999;
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar = "123";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = AddParamsWithoutMandatory(tooBigKeyVersion, srcParamSet, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest005
 * @tc.desc: tdd AddMandatoryParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest005");
    int32_t ret = AddMandatoryParams(nullptr, nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest006
 * @tc.desc: tdd AddMandatoryeParamsInCore, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest006");
    int32_t ret = AddMandatoryeParamsInCore(nullptr, nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest007
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest007");
    int32_t ret = AuthChangeProcessName(nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest008
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest008");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar = "HksUpgradeKeyCTest008";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    int32_t ret = AuthChangeProcessName(srcParamSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest009
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest009");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar = "short_name";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar2 = "long_name";
    struct HksBlob processName2 = { .size = strlen(processNameChar2), .data = (uint8_t *)processNameChar2 };
    struct HksParam processNameParam2 = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName2 };
    ret = HksAddParams(paramSet, &processNameParam2, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = AuthChangeProcessName(srcParamSet, paramSet);
    ASSERT_EQ(HKS_FAILURE, ret);

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest010
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest010");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;
    const char *processNameChar = "same_leng_name_1";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;

    struct HksParamSet *paramSet = nullptr;
    ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;
    const char *processNameChar2 = "same_leng_name_2";
    struct HksBlob processName2 = { .size = strlen(processNameChar2), .data = (uint8_t *)processNameChar2 };
    struct HksParam processNameParam2 = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName2 };
    ret = HksAddParams(paramSet, &processNameParam2, 1);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret) << "ret is " << ret;

    ret = AuthChangeProcessName(srcParamSet, paramSet);
    ASSERT_EQ(HKS_FAILURE, ret) << "ret is " << ret;

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest011
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest011");
    uint32_t tooBigKeySize = 4096;
    struct HksBlob wrongKey = { .size = tooBigKeySize, .data = nullptr };
    int32_t ret = HksUpgradeKey(nullptr, nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_BAD_STATE, ret) << "ret is " << ret;
}
}
