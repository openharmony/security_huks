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

#include <gtest/gtest.h>
#include "hks_bms_api_wrap.h"

using namespace testing::ext;
namespace Unittest::HksBmsApiWrapTest {
class HksBmsApiWrapTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksBmsApiWrapTest::SetUpTestCase(void)
{
}

void HksBmsApiWrapTest::TearDownTestCase(void)
{
}

void HksBmsApiWrapTest::SetUp()
{
}

void HksBmsApiWrapTest::TearDown()
{
}

/**
 * @tc.name: HksBmsApiWrapTest.HksBmsApiWrapTest001
 * @tc.desc: tdd
 * @tc.type: FUNC
 */
HWTEST_F(HksBmsApiWrapTest, HksBmsApiWrapTest001, TestSize.Level0)
{
    int32_t ret = GetCallerName(nullptr, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_NULL_POINTER);
}
}
