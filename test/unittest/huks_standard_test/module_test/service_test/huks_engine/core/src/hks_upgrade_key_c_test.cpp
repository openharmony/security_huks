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

#include "file_ex.h"
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
 * @tc.desc: tdd AddAlgParamsTags, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest001");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    struct HksParam algParam = { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES };
    ret = HksAddParams(srcParamSet, &algParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = AddAlgParamsTags(srcParamSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest002
 * @tc.desc: tdd HksAddkeyToParamSet, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest002");
    int32_t ret = HksAddkeyToParamSet(nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest003
 * @tc.desc: tdd AddMandatoryParamsInCore, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest003");
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = AddMandatoryParamsInCore(nullptr, paramSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest004
 * @tc.desc: tdd AddMandatoryParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest004");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar = "HksUpgradeKeyCTest004";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = AddMandatoryParams(srcParamSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest005
 * @tc.desc: tdd AddMandatoryParams, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest005");
    int32_t ret = AddMandatoryParams(nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest006
 * @tc.desc: tdd AddMandatoryParamsInCore, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest006");
    uint32_t exceedCnt = HKS_DEFAULT_PARAM_CNT + 1;
    struct HksParamSet paramSet = { .paramSetSize = 0, .paramsCnt = exceedCnt, .params = {} };
    int32_t ret = AddMandatoryParamsInCore(nullptr, &paramSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest007
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest007");
    int32_t ret = AuthChangeProcessName(nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest008
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_SUCCESS
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
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
    ret = AuthChangeProcessName(srcParamSet, nullptr);
    ASSERT_EQ(HKS_SUCCESS, ret);
    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest009
 * @tc.desc: tdd AuthChangeProcessName, expect HKS_FAILURE
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
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
    const char *processNameChar2 = "longlong_name";
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
 * @tc.require: issueI6RJBX
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
 * @tc.desc: tdd HksUpgradeKey, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest011");
    uint32_t tooBigKeySize = 4096;
    struct HksBlob wrongKey = { .size = tooBigKeySize, .data = nullptr };
    int32_t ret = HksUpgradeKey(&wrongKey, nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_BAD_STATE, ret) << "ret is " << ret;
}

/**
 * @tc.name: HksUpgradeKeyCTest.HksUpgradeKeyCTest012
 * @tc.desc: tdd AuthUpgradeKey, expect HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyCTest, HksUpgradeKeyCTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyCTest012");
    int32_t ret = AuthUpgradeKey(nullptr, nullptr);
    CleanParamSetKey(nullptr);
    ASSERT_EQ(HKS_ERROR_BAD_STATE, ret) << "ret is " << ret;
}
}
