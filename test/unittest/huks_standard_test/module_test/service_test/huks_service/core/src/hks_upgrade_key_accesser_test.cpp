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

#include "../../../../../../../../services/huks_standard/huks_service/main/core/src/hks_upgrade_key_accesser.c"

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
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest001
 * @tc.desc: tdd HksAddProcessNameToParamSet, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest001");
    int32_t ret = HksAddProcessNameToParamSet(nullptr, nullptr);
    ASSERT_EQ(HKS_FAILURE, ret);
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest002
 * @tc.desc: tdd HksAddProcessNameToParamSet, expect HKS_ERROR_PARAM_NOT_EXIST
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest002");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = HksAddProcessNameToParamSet(srcParamSet, nullptr);
    ASSERT_EQ(HKS_ERROR_PARAM_NOT_EXIST, ret);

    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest003
 * @tc.desc: tdd HksAddProcessNameToParamSet, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest003");
    struct HksParamSet *srcParamSet = nullptr;
    int32_t ret = HksInitParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);
    const char *processNameChar = "123";
    struct HksBlob processName = { .size = strlen(processNameChar), .data = (uint8_t *)processNameChar };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME, .blob = processName };
    ret = HksAddParams(srcParamSet, &processNameParam, 1);
    ASSERT_EQ(HKS_SUCCESS, ret);
    ret = HksBuildParamSet(&srcParamSet);
    ASSERT_EQ(HKS_SUCCESS, ret);

    ret = HksAddProcessNameToParamSet(srcParamSet, nullptr);
    ASSERT_EQ(HKS_ERROR_INVALID_ARGUMENT, ret);

    HksFreeParamSet(&srcParamSet);
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest004
 * @tc.desc: tdd AddMandatoryeParamsInService, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest004");

    int32_t ret = GetMandatoryParamsInService(nullptr, nullptr);
    ASSERT_EQ(HKS_FAILURE, ret);
}

/**
 * @tc.name: HksUpgradeKeyAccesserTest.HksUpgradeKeyAccesserTest005
 * @tc.desc: tdd HksDoUpgradeKeyAccess, expect HKS_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(HksUpgradeKeyAccesserTest, HksUpgradeKeyAccesserTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksUpgradeKeyAccesserTest005");

    int32_t ret = HksDoUpgradeKeyAccess(nullptr, nullptr, nullptr);
    ASSERT_EQ(HKS_FAILURE, ret);
}
}
