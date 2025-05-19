/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_generate_key_test_common.h"

#include <gtest/gtest.h>
#include <vector>

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace Unittest::HksAccessControlPartTest {
class HksAccessControlGenTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAccessControlGenTest::SetUpTestCase(void)
{
}

void HksAccessControlGenTest::TearDownTestCase(void)
{
}

void HksAccessControlGenTest::SetUp()
{
    ASSERT_EQ(HksInitialize(), 0);
}

void HksAccessControlGenTest::TearDown()
{
}

/**
 * @tc.name: HksAccessControlGenTest.HksAccessControlGenTest001
 * @tc.desc: test allow wrap key with access control;
 * @tc.type: FUNC
 */
HWTEST_F(HksAccessControlGenTest, HksAccessControlGenTest001, TestSize.Level0)
{
    static char keyAliasString[] = "HksWrapKeyAlias";
    static struct HksBlob keyAlias = { strlen(keyAliasString), (uint8_t *)keyAliasString };

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    EXPECT_EQ(ret, HKS_SUCCESS) << "init paramset fail";

    ret = HksAddParams(paramSet, g_genParamsCommon001, HKS_ARRAY_SIZE(g_genParamsCommon001));
    EXPECT_EQ(ret, HKS_SUCCESS) << "add params to paramset fail";

    ret = HksGenerateKey(&keyAlias, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_KEY_NOT_ALLOW_WRAP) << "HksGenerateKey HKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD";

    struct HksParam *keyAccessTypeParam = nullptr;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &keyAccessTypeParam);
    EXPECT_EQ(ret, HKS_SUCCESS) << "get access type param fail";

    keyAccessTypeParam->uint32Param = HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL;
    ret = HksGenerateKey(&keyAlias, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_KEY_NOT_ALLOW_WRAP) << "HksGenerateKey HKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL";

    keyAccessTypeParam->uint32Param = HKS_AUTH_ACCESS_ALWAYS_VALID;
    ret = HksGenerateKey(&keyAlias, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey HKS_AUTH_ACCESS_ALWAYS_VALID";

    HksFreeParamSet(&paramSet);
}
}