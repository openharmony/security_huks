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

#include <gtest/gtest.h>
#include <stdint.h>
#include "hks_error_code.h"
#include "hks_cpp_paramset.h"
#include "hks_report_generate_key.h"
#include "hks_report_list_aliases.h"
#include "hks_report_rename_key.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"

#include "hks_report_import_key.h"
#include "hks_report_delete_key.h"
#include "hks_report_check_key_exited.h"

using namespace testing::ext;
namespace Unittest::HksReportOneStageTest {
class HksReportOneStageTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportOneStageTest::SetUpTestCase(void)
{
}

void HksReportOneStageTest::TearDownTestCase(void)
{
}

void HksReportOneStageTest::SetUp()
{
}

void HksReportOneStageTest::TearDown()
{
}

char g_testCaller[] = "callerInfo";

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest001
 * @tc.desc: test report import
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest001, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = 0 },
        { .tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = 0 }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForImport(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksParamSetToEventInfoForImport(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForImport(nullptr);
    EXPECT_EQ(need, false);

    
    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_IMPORT_KEY, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_IMPORT_KEY, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForImport(&eventInfo1, &eventInfo2);
    HksEventInfoAddForImport(nullptr, nullptr);
}

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest002
 * @tc.desc: test report delete
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest002, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet(params);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForDelete(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForDelete(nullptr);
    EXPECT_EQ(need, false);

    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_DELETE_KEY, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_DELETE_KEY, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForDelete(&eventInfo1, &eventInfo2);
    HksEventInfoAddForDelete(nullptr, nullptr);
}

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest003
 * @tc.desc: test report key existed
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest003, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet(params);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForCheckKeyExited(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForCheckKeyExited(nullptr);
    EXPECT_EQ(need, false);

    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_DELETE_KEY, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_DELETE_KEY, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForCheckKeyExited(&eventInfo1, &eventInfo2);
    HksEventInfoAddForCheckKeyExited(nullptr, nullptr);
}

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest004
 * @tc.desc: test report generate key
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest004, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_AGREE_ALG, .uint32Param = 0 },
        { .tag = HKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS, .boolParam = false }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForKeyGen(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksParamSetToEventInfoForKeyGen(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForKeyGen(nullptr);
    EXPECT_EQ(need, false);

    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_GENERATE_KEY, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_GENERATE_KEY, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForKeyGen(&eventInfo1, &eventInfo2);
    HksEventInfoAddForKeyGen(nullptr, nullptr);
}

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest005
 * @tc.desc: test report list key alias
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest005, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet(params);
    EXPECT_NE(cppParamSet.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForListAliases(cppParamSet.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForListAliases(nullptr);
    EXPECT_EQ(need, false);

    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_LIST_ALIASES, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_LIST_ALIASES, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForListAliases(&eventInfo1, &eventInfo2);
    HksEventInfoAddForListAliases(nullptr, nullptr);
}

/**
 * @tc.name: HksReportOneStageTest.HksReportOneStageTest006
 * @tc.desc: test report generate key
 * @tc.type: FUNC
 */
HWTEST_F(HksReportOneStageTest, HksReportOneStageTest006, TestSize.Level0)
{
    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_PARAM6_UINT32, .uint32Param = 0 },
        { .tag = HKS_TAG_IS_COPY_NEW_KEY, .boolParam = false }
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForRename(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksParamSetToEventInfoForRename(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    bool need = HksEventInfoIsNeedReportForRename(nullptr);
    EXPECT_EQ(need, false);

    struct HksEventInfo eventInfo1{ .common.eventId = HKS_EVENT_RENAME_KEY, .common.callerInfo.name = g_testCaller };
    struct HksEventInfo eventInfo2{ .common.eventId = HKS_EVENT_RENAME_KEY, .common.callerInfo.name = g_testCaller };
    HksEventInfoAddForRename(&eventInfo1, &eventInfo2);
    HksEventInfoAddForRename(nullptr, nullptr);
}

}