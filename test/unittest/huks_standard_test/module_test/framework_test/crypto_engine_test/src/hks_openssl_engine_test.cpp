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

#include "hks_openssl_engine_test.h"

#include <gtest/gtest.h>

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "file_ex.h"
#include "hks_api.h"
#include "hks_openssl_engine.h"
#include "hks_crypto_hal.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkOpensslEngineTest {
class HksFrameworkOpensslEngineTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkOpensslEngineTest::SetUpTestCase(void)
{
}

void HksFrameworkOpensslEngineTest::TearDownTestCase(void)
{
}

void HksFrameworkOpensslEngineTest::SetUp()
{
}

void HksFrameworkOpensslEngineTest::TearDown()
{
}

/**
 * @tc.name: HksFrameworkOpensslEngineTest.HksFrameworkOpensslEngineTest001
 * @tc.desc: test HksCryptoHalGetPubKey
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslEngineTest, HksFrameworkOpensslEngineTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslEngineTest001");
    uint8_t data[4] = { 0 };
    HksBlob blob = {
        .size = 4,
        .data = data,
    };

    int32_t ret = HksCryptoHalGetPubKey(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest001 failed, ret = " << ret;

    ret = HksCryptoHalGetPubKey(&blob, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest001 failed, ret = " << ret;

    ret = HksCryptoHalGetPubKey(&blob, &blob);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_SIZE) << "HksFrameworkOpensslEngineTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslEngineTest.HksFrameworkOpensslEngineTest002
 * @tc.desc: test HksCryptoHalHmacFinal
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslEngineTest, HksFrameworkOpensslEngineTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslEngineTest002");
    uint8_t data[4] = { 0 };
    HksBlob blob = {
        .size = 4,
        .data = data,
    };

    int32_t ret = HksCryptoHalHmacFinal(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest002 failed, ret = " << ret;

    ret = HksCryptoHalHmacFinal(&blob, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest002 failed, ret = " << ret;

    void *ctx = nullptr;
    ret = HksCryptoHalHmacFinal(&blob, &ctx, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest002 failed, ret = " << ret;

    void *ctxTwo = HksMalloc(8);
    ret = HksCryptoHalHmacFinal(&blob, &ctxTwo, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslEngineTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslEngineTest.HksFrameworkOpensslEngineTest003
 * @tc.desc: test HksCryptoHalDecryptFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslEngineTest, HksFrameworkOpensslEngineTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslEngineTest003");
    HksCryptoHalDecryptFreeCtx(nullptr, HKS_ALG_AES);
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

}