/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_report_common.h"

#include <gtest/gtest.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report_three_stage.h"
#include "hks_report_three_stage_build.h"
#include "hks_cpp_paramset.h"

using namespace testing::ext;
namespace Unittest::HksReportCommonTest {
class HksReportCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportCommonTest::SetUpTestCase(void)
{
}

void HksReportCommonTest::TearDownTestCase(void)
{
}

void HksReportCommonTest::SetUp()
{
}

void HksReportCommonTest::TearDown()
{
}

static int32_t GenerateParamSet(struct HksParamSet **paramSet, const struct HksParam tmpParams[], uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksInitParamSet failed");
        return ret;
    }

    if (tmpParams != NULL) {
        ret = HksAddParams(*paramSet, tmpParams, paramCount);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksAddParams failed");
            HksFreeParamSet(paramSet);
            return ret;
        }
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksBuildParamSet failed");
        HksFreeParamSet(paramSet);
        return ret;
    }
    return ret;
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest001
 * @tc.desc: tdd GetCommonEventInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest001");

    uint8_t arr00 = 0;
    uint8_t arr0 = 0;
    uint8_t arr1 = 0;
    uint8_t arr2 = 0;
    uint8_t arr3 = 0;
    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_PARAM0_NULL, .blob = { .size = 1, .data = &arr00 } },
        { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_PARAM0_BUFFER, .blob = { .size = 1, .data = &arr0 } },
        { .tag = HKS_TAG_PARAM1_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_PARAM1_BUFFER, .blob = { .size = 1, .data = &arr1 } },
        { .tag = HKS_TAG_PARAM2_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_PARAM2_BUFFER, .blob = { .size = 1, .data = &arr2 } },
        { .tag = HKS_TAG_PARAM3_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { .size = 1, .data = &arr3 } }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo = {};
    ret = GetCommonEventInfo(paramSet, &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest002
 * @tc.desc: tdd CheckEventCommonAndKey
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest002");

    char name1[] = "test_name";
    char name2[] = "test_name";
    struct HksEventInfo info1 = { .common.callerInfo.name = name1 };
    struct HksEventInfo info2 = { .common.callerInfo.name = name2 };

    info1.agreeDeriveInfo.keyInfo = { 0 };
    info2.agreeDeriveInfo.keyInfo = { 0 };
    info1.common.eventId = HKS_EVENT_DERIVE;
    info2.common.eventId = HKS_EVENT_DERIVE;
    bool ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, true);

    info1.common.eventId = HKS_EVENT_AGREE;
    info2.common.eventId = HKS_EVENT_AGREE;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, true);

    info1.generateInfo.keyInfo = { 0 };
    info2.generateInfo.keyInfo = { 0 };
    info1.common.eventId = HKS_EVENT_GENERATE_KEY;
    info2.common.eventId = HKS_EVENT_GENERATE_KEY;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, true);

    info1.keyInfo = { 0 };
    info2.keyInfo = { 0 };
    info1.common.eventId = HKS_EVENT_DELETE_KEY;
    info2.common.eventId = HKS_EVENT_DELETE_KEY;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, false);

    info1.importInfo.keyInfo = { 0 };
    info2.importInfo.keyInfo = { 0 };
    info1.common.eventId = HKS_EVENT_IMPORT_KEY;
    info2.common.eventId = HKS_EVENT_IMPORT_KEY;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, true);

    info1.renameInfo.keyInfo = { 0 };
    info2.renameInfo.keyInfo = { 0 };
    info1.common.eventId = HKS_EVENT_RENAME_KEY;
    info2.common.eventId = HKS_EVENT_RENAME_KEY;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, false);

    info1.common.eventId = HKS_EVENT_ATTEST;
    info2.common.eventId = HKS_EVENT_ATTEST;
    ret = CheckEventCommonAndKey(&info1, &info2);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest003
 * @tc.desc: tdd GetEventKeyInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest003");

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_PARAM4_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = 0 },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = 0 },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = 0 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = 0 },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 0 },
        { .tag = HKS_TAG_KEY_FLAG, .uint32Param = 0 },
        { .tag = HKS_TAG_PARAM5_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_IS_BATCH_OPERATION, .boolParam = true },
        { .tag = HKS_TAG_BATCH_PURPOSE, .uint32Param = 0 },
        { .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT, .uint32Param = 0 }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventKeyInfo keyInfo = { 0 };
    ret = GetEventKeyInfo(paramSet, &keyInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest004
 * @tc.desc: tdd GetEventKeyAccessInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest004");

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = 0  },
        { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = 0 },
        { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = 0  },
        { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = 0 },
        { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = 0  },
        { .tag = HKS_TAG_FRONT_USER_ID, .uint32Param = 0 },
        { .tag = HKS_TAG_USER_AUTH_MODE, .uint32Param = 0  },
        { .tag = HKS_TAG_IS_DEVICE_PASSWORD_SET, .boolParam = true }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventKeyAccessInfo keyAccessInfo = { 0 };
    ret = GetEventKeyAccessInfo(paramSet, &keyAccessInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest005
 * @tc.desc: tdd GetCommonEventInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest005");

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventInfo eventInfo = {};
    ret = GetCommonEventInfo(paramSet, &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest006
 * @tc.desc: tdd GetEventKeyInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest006");

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventKeyInfo keyInfo = { 0 };
    ret = GetEventKeyInfo(paramSet, &keyInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest007
 * @tc.desc: tdd GetEventKeyAccessInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest007");

    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = GenerateParamSet(&paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksEventKeyAccessInfo keyAccessInfo = { 0 };
    ret = GetEventKeyAccessInfo(paramSet, &keyAccessInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest008
 * @tc.desc: tdd AddTimeCost
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksReportCommonTest008");

    uint64_t startTime = 0xffffffffffffffff;
    int32_t ret = AddTimeCost(nullptr, startTime);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest009
 * @tc.desc: test BuildCommonInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest009, TestSize.Level0)
{
    char testInfo[] = "this is a test";
    struct HksEventInfo eventInfo{};
    struct timespec timeSpec{};
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { sizeof(HksEventInfo), (uint8_t *)&eventInfo } },
        { .tag = HKS_TAG_PARAM0_BUFFER, .blob = { strlen(testInfo) + 1, (uint8_t *)testInfo } },
        { .tag = HKS_TAG_PARAM1_BUFFER, .blob = { sizeof(struct timespec), (uint8_t *)&timeSpec } },
        { .tag = HKS_TAG_PARAM2_BUFFER, .blob = { strlen(testInfo) + 1, (uint8_t *)testInfo } },
        { .tag = HKS_TAG_PARAM0_NULL,   .blob = { strlen(testInfo) + 1, (uint8_t *)testInfo } },
        { .tag = HKS_TAG_TRACE_ID,      .blob = { strlen(testInfo) + 1, (uint8_t *)testInfo } },
        { .tag = HKS_TAG_PARAM1_UINT32, .uint32Param = 0 }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = BuildCommonInfo(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = BuildCommonInfo(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_FAILURE);

    std::vector<HksParam> params3{ 
        { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { sizeof(HksEventInfo), (uint8_t *)&eventInfo } } 
    };
    CppParamSet cppParamSet3(params3);
    EXPECT_NE(cppParamSet3.GetParamSet(), nullptr);
    ret = BuildCommonInfo(cppParamSet3.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksReportCommonTest.HksReportCommonTest010
 * @tc.desc: test HksFreeEventInfo && AddEventInfoCommon
 * @tc.type: FUNC
 */
HWTEST_F(HksReportCommonTest, HksReportCommonTest010, TestSize.Level0)
{
    std::vector<HksParam> params{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet(params);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);

    struct HksEventInfo eventInfo{ .common.eventId = HKS_EVENT_DATA_SIZE_STATISTICS };
    int32_t ret = BuildCommonInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_FAILURE);
    
    eventInfo.common.eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER;
    ret = BuildCommonInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_FAILURE);

    eventInfo.common.eventId = HKS_EVENT_UKEY_END + 1;
    ret = BuildCommonInfo(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_FAILURE);

    struct HksEventInfo eventInfo1{ .common.statInfo.dataLen = UINT32_MAX, .common.statInfo.totalCost = UINT32_MAX };
    struct HksEventInfo eventInfo2{ .common.statInfo.dataLen = UINT32_MAX, .common.statInfo.totalCost = UINT32_MAX };
    AddEventInfoCommon(&eventInfo1, &eventInfo2);

    eventInfo1.common.statInfo.dataLen = 1;
    eventInfo1.common.statInfo.totalCost = 1;
    eventInfo2.common.statInfo.dataLen = 1;
    eventInfo2.common.statInfo.totalCost = 1;
    AddEventInfoCommon(&eventInfo1, &eventInfo2);
}

}
 