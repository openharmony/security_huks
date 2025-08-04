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
#include <gtest/gtest.h>

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
}

/**
 * @tc.name: HksReportDataSizeTest.HksReportDataSizeTest002
 * @tc.desc: tdd
 * @tc.type: FUNC
 */
HWTEST_F(HksReportDataSizeTest, HksReportDataSizeTest002, TestSize.Level0)
{
    int userId = 0;
    ReportDataSizeEvent(userId);
    EXPECT_EQ(userId, 0);
}
}
