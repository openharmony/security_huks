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

#include "hks_report_data_size.h"
#include "hks_cpp_paramset.h"
#include <gtest/gtest.h>
#include <string.h>

using namespace testing::ext;
namespace Unittest::HksReportDataSizeTest {
class HksReportDataSizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportDataSizeTest::SetUpTestCase(void)
{
}

void HksReportDataSizeTest::TearDownTestCase(void)
{
}

void HksReportDataSizeTest::SetUp()
{
}

void HksReportDataSizeTest::TearDown()
{
}

constexpr static char COMPONENT_NAME1[] = "HUKS";
constexpr static char PARTITION_NAME1[] = "/data";
constexpr static char FOLDER_PATH1[] = "huks_folder_path_test";
constexpr static char FOLDER_SIZE1[] = "huks_folder_size_test";
constexpr static uint64_t DEVICE_VALID_SIZE = 1024;

/**
 * @tc.name: HksReportDataSizeTest.HksReportDataSizeTest001
 * @tc.desc: tdd
 * @tc.type: FUNC
 */
HWTEST_F(HksReportDataSizeTest, HksReportDataSizeTest001, TestSize.Level0)
{
    struct HksEventInfo *dstEventInfo = nullptr;
    struct HksEventInfo *srcEventInfo = nullptr;
    HksEventInfoAddForDataSize(dstEventInfo, srcEventInfo);
    EXPECT_EQ(dstEventInfo, nullptr);
    EXPECT_EQ(srcEventInfo, nullptr);

    struct HksEventInfo eventInfo{};
    std::vector<HksParam> params1{
        { .tag = HKS_TAG_REMAIN_PARTITION_SIZE, .uint64Param = DEVICE_VALID_SIZE },
        { .tag = HKS_TAG_COMPONENT_NAME, .blob = { strlen(COMPONENT_NAME1) + 1, (uint8_t *)COMPONENT_NAME1 } },
        { .tag = HKS_TAG_PARTITION_NAME, .blob = { strlen(PARTITION_NAME1) + 1, (uint8_t *)PARTITION_NAME1 } },
        { .tag = HKS_TAG_FILE_OF_FOLDER_PATH, .blob = { strlen(FOLDER_PATH1) + 1, (uint8_t *)FOLDER_PATH1 } },
        { .tag = HKS_TAG_FILE_OF_FOLDER_SIZE, .blob = { strlen(FOLDER_SIZE1) + 1, (uint8_t *)FOLDER_SIZE1 }}
    };
    CppParamSet cppParamSet1(params1);
    EXPECT_NE(cppParamSet1.GetParamSet(), nullptr);
    int32_t ret = HksParamSetToEventInfoForDataSize(cppParamSet1.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::vector<HksParam> params2{ { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = 0 } };
    CppParamSet cppParamSet2(params2);
    EXPECT_NE(cppParamSet2.GetParamSet(), nullptr);
    ret = HksParamSetToEventInfoForDataSize(cppParamSet2.GetParamSet(), &eventInfo);
    EXPECT_EQ(ret, HKS_SUCCESS);

    std::unordered_map<std::string, std::string> reportData{};
    ret = HksEventInfoToMapForDataSize(&eventInfo, reportData);

    int userId = 0;
    ReportDataSizeEvent(userId);
    EXPECT_EQ(userId, 0);
}

}
