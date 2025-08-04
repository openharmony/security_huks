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

#include "hks_report_rename_key.h"
#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksReportRenameKeyTest {
class HksReportRenameKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksReportRenameKeyTest::SetUpTestCase(void)
{
}

void HksReportRenameKeyTest::TearDownTestCase(void)
{
}

void HksReportRenameKeyTest::SetUp()
{
}

void HksReportRenameKeyTest::TearDown()
{
}

/**
 * @tc.name: HksReportRenameKeyTest.HksReportRenameKeyTest001
 * @tc.desc: tdd
 * @tc.type: FUNC
 */
HWTEST_F(HksReportRenameKeyTest, HksReportRenameKeyTest001, TestSize.Level0)
{
    struct HksEventInfo *dstEventInfo = nullptr;
    struct HksEventInfo *srcEventInfo = nullptr;
    HksEventInfoAddForRename(dstEventInfo, srcEventInfo);
    EXPECT_EQ(dstEventInfo, nullptr);
    EXPECT_EQ(srcEventInfo, nullptr);
}
}
