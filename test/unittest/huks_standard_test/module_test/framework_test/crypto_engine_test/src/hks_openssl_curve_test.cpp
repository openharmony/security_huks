/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_openssl_curve_test.h"

#include <cstring>
#include <gtest/gtest.h>

#include "base/security/huks/frameworks/huks_standard/main/crypto_engine/openssl/src/hks_openssl_ed25519tox25519.c"
#include "file_ex.h"
#include "hks_api.h"
#include "hks_openssl_ed25519tox25519.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksFrameworkCurveEngineTest {
class HksCurveEngineTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCurveEngineTest::SetUpTestCase(void)
{
}

void HksCurveEngineTest::TearDownTestCase(void)
{
}

void HksCurveEngineTest::SetUp()
{
}

void HksCurveEngineTest::TearDown()
{
}

/**
 * @tc.name: HksCurveEngineTest.HksCurveEngineTest001
 * @tc.desc: tdd HksCurveEngineTest001, function is Curve25519Initialize
 * @tc.type: FUNC
 */
HWTEST_F(HksCurveEngineTest, HksCurveEngineTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCurveEngineTest001");
    int32_t ret = Curve25519Initialize(nullptr, nullptr, 0, true);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksCurveEngineTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksCurveEngineTest.HksCurveEngineTest002
 * @tc.desc: tdd HksCurveEngineTest002, function is Curve25519Destroy
 * @tc.type: FUNC
 */
HWTEST_F(HksCurveEngineTest, HksCurveEngineTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCurveEngineTest002");
    Curve25519Structure str = {
        .p = nullptr,
        .d = nullptr,
        .negativeTwo = nullptr,
        .negativeOne = nullptr,
        .negativeOneDivideTwo = nullptr,
        .ed25519Pubkey = nullptr,
    };
    Curve25519Destroy(&str);
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksCurveEngineTest.HksCurveEngineTest003
 * @tc.desc: tdd HksCurveEngineTest003, function is FreeLocalBigVar
 * @tc.type: FUNC
 */
HWTEST_F(HksCurveEngineTest, HksCurveEngineTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCurveEngineTest003");
    Curve25519Var var = {
        .a = nullptr,
        .b = nullptr,
        .c = nullptr,
    };
    FreeLocalBigVar(&var);
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksCurveEngineTest.HksCurveEngineTest004
 * @tc.desc: tdd HksCurveEngineTest004, function is Curve25519LocalVar
 * @tc.type: FUNC
 */
HWTEST_F(HksCurveEngineTest, HksCurveEngineTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCurveEngineTest004");
    Curve25519Var var = {
        .a = nullptr,
        .b = nullptr,
        .c = nullptr,
    };
    Curve25519LocalVar(&var);
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

}