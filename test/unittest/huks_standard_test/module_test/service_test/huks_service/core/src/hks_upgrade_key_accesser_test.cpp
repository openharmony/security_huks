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

#include "hks_upgrade_key_accesser_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_service/main/core/src/hks_upgrade_key_accesser.c"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksUpgradeKeyAccesserTest {
class HksUpgradeKeyAccesserTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUpgradeKeyAccesserTest::SetUpTestCase(void)
{
}

void HksUpgradeKeyAccesserTest::TearDownTestCase(void)
{
}

void HksUpgradeKeyAccesserTest::SetUp()
{
}

void HksUpgradeKeyAccesserTest::TearDown()
{
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest004
 * @tc.desc: tdd AddMandatoryeParamsInService, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest004");

    int32_t ret = AddMandatoryParamsInService(nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest005
 * @tc.desc: tdd HksDoUpgradeKeyAccess, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 * @tc.require: issueI6RJBX
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest005");

    int32_t ret = HksDoUpgradeKeyAccess(nullptr, nullptr, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);
}
}
