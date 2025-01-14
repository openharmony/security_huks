/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_file_transfer.h"
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::HksFileTransferTest {
class HksFileTransferTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFileTransferTest::SetUpTestCase(void)
{
}

void HksFileTransferTest::TearDownTestCase(void)
{
}

void HksFileTransferTest::SetUp()
{
}

void HksFileTransferTest::TearDown()
{
}

/**
 * @tc.name: HksFileTransferTest.HksFileTransferTest001
 * @tc.desc: tdd HksUpgradeFileTransferOnUserUnlock
 * @tc.type: FUNC
 */
HWTEST_F(HksFileTransferTest, HksFileTransferTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFileTransferTest001");
    EXPECT_EQ(HKS_SUCCESS, HksUpgradeFileTransferOnUserUnlock(100));
}
}
