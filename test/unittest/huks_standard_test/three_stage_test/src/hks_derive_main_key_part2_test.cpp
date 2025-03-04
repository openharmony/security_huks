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

#include "hks_api.h"
#include "hks_apply_permission_test_common.h"
#include "hks_derive_main_key_test_common.h"
#include "hks_three_stage_test_common.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksDeriveMainKeyTest {
class HksDeriveMainKeyPart2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDeriveMainKeyPart2Test::SetUpTestCase(void)
{
}

void HksDeriveMainKeyPart2Test::TearDownTestCase(void)
{
}

void HksDeriveMainKeyPart2Test::SetUp()
{
}

void HksDeriveMainKeyPart2Test::TearDown()
{
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test001
 * @tc.desc: generate de key before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test001, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias1 = { strlen(g_tmpKeyAlias1), (uint8_t *)g_tmpKeyAlias1 };
    ret = HksGenerateKey(&keyAlias1, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test002
 * @tc.desc: generate ce key before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test002, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias2 = { strlen(g_tmpKeyAlias2), (uint8_t *)g_tmpKeyAlias2 };
    ret = HksGenerateKey(&keyAlias2, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test003
 * @tc.desc: generate ece key before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test003, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias3 = { strlen(g_tmpKeyAlias3), (uint8_t *)g_tmpKeyAlias3 };
    ret = HksGenerateKey(&keyAlias3, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test004
 * @tc.desc: generate de key and set ciphertext before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test004, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, g_genParams001, sizeof(g_genParams001) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias4 = { strlen(g_tmpKeyAlias4), (uint8_t *)g_tmpKeyAlias4 };
    ret = HksImportKey(&keyAlias4, genParamSet, &keyImported);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test005
 * @tc.desc: generate ce key and set ciphertext before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test005, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams002, sizeof(g_genParams002) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias5 = { strlen(g_tmpKeyAlias5), (uint8_t *)g_tmpKeyAlias5 };
    ret = HksImportKey(&keyAlias5, genParamSet, &keyImported);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    HksFreeParamSet(&genParamSet);
}

/**
 * @tc.name: HksDeriveMainKeyPart2Test.HksDeriveMainKeyPart2Test006
 * @tc.desc: generate ece key and set ciphertext before upgrading huk2
 * @tc.type: FUNC
 */
HWTEST_F(HksDeriveMainKeyPart2Test, HksDeriveMainKeyPart2Test006, TestSize.Level0)
{
    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *genParamSet = nullptr;
    ret = InitParamSet(&genParamSet, g_genParams003, sizeof(g_genParams003) / sizeof(HksParam));
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet failed.";

    const struct HksBlob keyAlias6 = { strlen(g_tmpKeyAlias6), (uint8_t *)g_tmpKeyAlias6 };
    ret = HksImportKey(&keyAlias6, genParamSet, &keyImported);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksImportKey failed.";

    HksFreeParamSet(&genParamSet);
}
}
