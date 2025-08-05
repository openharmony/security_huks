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
#include "hks_permission_check.h"

using namespace testing::ext;
namespace Unittest::HksPermissionCheckTest {
class HksPermissionCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksPermissionCheckTest::SetUpTestCase(void)
{
}

void HksPermissionCheckTest::TearDownTestCase(void)
{
}

void HksPermissionCheckTest::SetUp()
{
}

void HksPermissionCheckTest::TearDown()
{
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest001
 * @tc.desc: tdd SensitivePermissionCheck
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest001, TestSize.Level0)
{
    const char permission[] = "test_permission";
    int32_t ret = SensitivePermissionCheck(permission);
    EXPECT_EQ(ret, HKS_ERROR_NO_PERMISSION);
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest002
 * @tc.desc: tdd SystemApiPermissionCheck
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest002, TestSize.Level0)
{
    int32_t ret = SystemApiPermissionCheck(0);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksPermissionCheckTest.HksPermissionCheckTest003
 * @tc.desc: tdd HksCheckAcrossAccountsPermission
 * @tc.type: FUNC
 */
HWTEST_F(HksPermissionCheckTest, HksPermissionCheckTest003, TestSize.Level0)
{
    int32_t ret = HksCheckAcrossAccountsPermission(nullptr, 0);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}
}
