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

#include "hks_report_sa_event.h"

#include <gtest/gtest.h>
#include <string.h>
#include <stdlib.h>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include "hks_cpp_paramset.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "securec.h"

using namespace testing::ext;
namespace Unittest::HksReportSaEventTest {
class HksReportSaEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportSaEventTest::SetUpTestCase(void)
{
}

void HksReportSaEventTest::TearDownTestCase(void)
{
}

void HksReportSaEventTest::SetUp()
{
}

void HksReportSaEventTest::TearDown()
{
}

constexpr static char FUNC_ON_START[] = "OnStart";
constexpr static char FUNC_ON_ADD[] = "OnAddSystemAbility";
constexpr static char CALLER_NAME_A[] = "caller_a";
constexpr static char CALLER_NAME_B[] = "caller_b";
constexpr static int32_t TEST_ERROR_CODE = 12000012; /* HUKS_ERR_CODE_EXTERNAL_ERROR */

static char *DupStr(const char *src)
{
    uint32_t len = strlen(src) + 1;
    char *dst = static_cast<char *>(HksMalloc(len));
    if (dst != nullptr) {
        (void)memcpy_s(dst, len, src, len);
    }
    return dst;
}

static void InitSaEventInfo(struct HksEventInfo *eventInfo, uint32_t eventId, const char *callerName)
{
    (void)memset_s(eventInfo, sizeof(struct HksEventInfo), 0, sizeof(struct HksEventInfo));
    eventInfo->common.eventId = eventId;
    eventInfo->common.count = 1;
    eventInfo->common.callerInfo.name = DupStr(callerName);
    eventInfo->common.function = DupStr(FUNC_ON_START);
    eventInfo->common.result.code = TEST_ERROR_CODE;
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest001
 * @tc.desc: tdd HksParamSetToEventInfoForSaEvent, cover null params and normal paramset
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest001, TestSize.Level0)
{
    int32_t ret = HksParamSetToEventInfoForSaEvent(nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    struct HksEventInfo eventInfo{};
    ret = HksParamSetToEventInfoForSaEvent(nullptr, &eventInfo);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    std::vector<HksParam> emptyParams{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppEmptyParamSet(emptyParams);
    EXPECT_NE(cppEmptyParamSet.GetParamSet(), nullptr);
    ret = HksParamSetToEventInfoForSaEvent(cppEmptyParamSet.GetParamSet(), nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    ret = HksParamSetToEventInfoForSaEvent(cppEmptyParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct timespec time = {0};
    (void)timespec_get(&time, TIME_UTC);
    struct HksEventResultInfo resultInfo = {
        .code = TEST_ERROR_CODE,
        .module = 0,
        .stage = 0,
        .errMsg = nullptr
    };
    std::vector<HksParam> params{
        { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL },
        { .tag = HKS_TAG_PARAM0_BUFFER, .blob = { strlen(FUNC_ON_START) + 1, (uint8_t *)FUNC_ON_START } },
        { .tag = HKS_TAG_PARAM1_BUFFER, .blob = { sizeof(time), (uint8_t *)&time } },
        { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { sizeof(resultInfo), (uint8_t *)&resultInfo } },
    };
    CppParamSet cppParamSet(params);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);

    struct HksEventInfo saEventInfo{};
    ret = HksParamSetToEventInfoForSaEvent(cppParamSet.GetParamSet(), &saEventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);
    EXPECT_EQ(saEventInfo.common.eventId, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL);
    EXPECT_STREQ(saEventInfo.common.function, FUNC_ON_START);
    EXPECT_EQ(saEventInfo.common.result.code, TEST_ERROR_CODE);
    EXPECT_EQ(saEventInfo.common.count, 1);
    HKS_FREE(saEventInfo.common.function);
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest002
 * @tc.desc: tdd HksEventInfoIsNeedReportForSaEvent, always return true for valid eventInfo
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest002, TestSize.Level0)
{
    EXPECT_EQ(HksEventInfoIsNeedReportForSaEvent(nullptr), false);

    struct HksEventInfo eventInfo{};
    InitSaEventInfo(&eventInfo, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    /* this event is enqueued only when the subscribe fails, so it always needs to be reported */
    EXPECT_EQ(HksEventInfoIsNeedReportForSaEvent(&eventInfo), true);

    eventInfo.common.result.code = HKS_SUCCESS;
    EXPECT_EQ(HksEventInfoIsNeedReportForSaEvent(&eventInfo), true);

    HKS_FREE(eventInfo.common.callerInfo.name);
    HKS_FREE(eventInfo.common.function);
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest003
 * @tc.desc: tdd HksEventInfoIsEqualForSaEvent, cover null input and equal/unequal cases
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest003, TestSize.Level0)
{
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(nullptr, nullptr), false);

    struct HksEventInfo eventInfoA1{};
    struct HksEventInfo eventInfoA2{};
    struct HksEventInfo eventInfoB{};
    struct HksEventInfo eventInfoNoName{};

    InitSaEventInfo(&eventInfoA1, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    InitSaEventInfo(&eventInfoA2, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    InitSaEventInfo(&eventInfoB, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_B);
    InitSaEventInfo(&eventInfoNoName, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    HKS_FREE(eventInfoNoName.common.callerInfo.name);
    eventInfoNoName.common.callerInfo.name = nullptr;

    /* null input */
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(&eventInfoA1, nullptr), false);
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(nullptr, &eventInfoA1), false);
    /* null caller name */
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(&eventInfoNoName, &eventInfoA1), false);
    /* same eventId and same caller name */
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(&eventInfoA1, &eventInfoA2), true);
    /* different caller name */
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(&eventInfoA1, &eventInfoB), false);

    eventInfoB.common.eventId = HKS_EVENT_DATA_SIZE_STATISTICS;
    /* different eventId */
    EXPECT_EQ(HksEventInfoIsEqualForSaEvent(&eventInfoA1, &eventInfoB), false);

    HKS_FREE(eventInfoA1.common.callerInfo.name);
    HKS_FREE(eventInfoA1.common.function);
    HKS_FREE(eventInfoA2.common.callerInfo.name);
    HKS_FREE(eventInfoA2.common.function);
    HKS_FREE(eventInfoB.common.callerInfo.name);
    HKS_FREE(eventInfoB.common.function);
    HKS_FREE(eventInfoNoName.common.function);
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest004
 * @tc.desc: tdd HksEventInfoAddForSaEvent, cover null input, unequal and equal aggregation
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest004, TestSize.Level0)
{
    HksEventInfoAddForSaEvent(nullptr, nullptr);

    struct HksEventInfo eventInfoA1{};
    struct HksEventInfo eventInfoA2{};
    struct HksEventInfo eventInfoB{};
    InitSaEventInfo(&eventInfoA1, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    InitSaEventInfo(&eventInfoA2, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);
    InitSaEventInfo(&eventInfoB, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_B);

    /* null input */
    HksEventInfoAddForSaEvent(&eventInfoA1, nullptr);
    EXPECT_EQ(eventInfoA1.common.count, 1);
    HksEventInfoAddForSaEvent(nullptr, &eventInfoA2);

    /* unequal caller name, no aggregation */
    HksEventInfoAddForSaEvent(&eventInfoA1, &eventInfoB);
    EXPECT_EQ(eventInfoA1.common.count, 1);

    /* equal, count increments and time refreshes */
    eventInfoA2.common.count = 5;
    eventInfoA2.common.time.tv_sec = 12345;
    HksEventInfoAddForSaEvent(&eventInfoA1, &eventInfoA2);
    EXPECT_EQ(eventInfoA1.common.count, 2);
    EXPECT_EQ(eventInfoA1.common.time.tv_sec, 12345);

    HKS_FREE(eventInfoA1.common.callerInfo.name);
    HKS_FREE(eventInfoA1.common.function);
    HKS_FREE(eventInfoA2.common.callerInfo.name);
    HKS_FREE(eventInfoA2.common.function);
    HKS_FREE(eventInfoB.common.callerInfo.name);
    HKS_FREE(eventInfoB.common.function);
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest005
 * @tc.desc: tdd HksEventInfoToMapForSaEvent, cover null input, normal and unknown function
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest005, TestSize.Level0)
{
    std::unordered_map<std::string, std::string> reportData{};
    int32_t ret = HksEventInfoToMapForSaEvent(nullptr, reportData);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);

    struct HksEventInfo eventInfo{};
    InitSaEventInfo(&eventInfo, HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL, CALLER_NAME_A);

    ret = HksEventInfoToMapForSaEvent(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    /* function is null, reported as unknown */
    HKS_FREE(eventInfo.common.function);
    eventInfo.common.function = nullptr;
    reportData.clear();
    ret = HksEventInfoToMapForSaEvent(&eventInfo, reportData);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HKS_FREE(eventInfo.common.callerInfo.name);
}

/**
 * @tc.name: HksReportSaEventTest.HksReportSaEventTest006
 * @tc.desc: tdd ReportSubscribeSystemEventFail, cover null funcName and normal enqueue
 * @tc.type: FUNC
 */
HWTEST_F(HksReportSaEventTest, HksReportSaEventTest006, TestSize.Level0)
{
    /* null funcName, return directly without crash */
    ReportSubscribeSystemEventFail(nullptr, TEST_ERROR_CODE);

    /* normal cases, enqueued to the ha event queue */
    ReportSubscribeSystemEventFail(FUNC_ON_START, TEST_ERROR_CODE);
    ReportSubscribeSystemEventFail(FUNC_ON_ADD, TEST_ERROR_CODE);
    ReportSubscribeSystemEventFail(FUNC_ON_START, HKS_SUCCESS);
}

}
