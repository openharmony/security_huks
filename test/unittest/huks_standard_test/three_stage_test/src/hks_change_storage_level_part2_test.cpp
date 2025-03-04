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

#include "hks_api.h"
#include "hks_apply_permission_test_common.h"
#include "hks_change_storage_level_test_common.h"
#include "hks_three_stage_test_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksChangeStorageLevelTest {
class HksChangeStorageLevelPart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksChangeStorageLevelPart2Test::SetUpTestCase(void)
{
}

void HksChangeStorageLevelPart2Test::TearDownTestCase(void)
{
}

void HksChangeStorageLevelPart2Test::SetUp()
{
}

void HksChangeStorageLevelPart2Test::TearDown()
{
}

/**
 * @tc.name: HksChangeStorageLevelPart2Test.HksChangeStorageLevelPart2Test001
 * @tc.desc: upgrade DE to CE
 * @tc.type: FUNC
 */
HWTEST_F(HksChangeStorageLevelPart2Test, HksChangeStorageLevelPart2Test001, TestSize.Level0)
{
    HKS_LOG_I("Enter HksChangeStorageLevelPart2Test001");

    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    char tmpKeyAlias[] = "HksChangeStorageLevelPart2Test001";
    const struct HksBlob keyAlias = { strlen(tmpKeyAlias), (uint8_t *)tmpKeyAlias };
    struct HksParamSet *srcParamSet = nullptr;
    ret = InitParamSet(&srcParamSet, g_params001, sizeof(g_params001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksGenerateKey(&keyAlias, srcParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *desParamSet = nullptr;
    ret = InitParamSet(&desParamSet, g_params002, sizeof(g_params002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    ret = HksChangeStorageLevel(&keyAlias, srcParamSet, desParamSet);
    EXPECT_EQ(ret, HKS_ERROR_KEY_CLEAR_FAILED) << "HksChangeStorageLevel failed.";

    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&desParamSet);
}
}