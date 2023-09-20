/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "hks_openssl_hash_test.h"

#include <gtest/gtest.h>

#include "hks_openssl_hash.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkOpensslHashTest {
class HksFrameworkOpensslHashTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkOpensslHashTest::SetUpTestCase(void)
{
}

void HksFrameworkOpensslHashTest::TearDownTestCase(void)
{
}

void HksFrameworkOpensslHashTest::SetUp()
{
}

void HksFrameworkOpensslHashTest::TearDown()
{
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest001
 * @tc.desc: test HksOpensslHashInit, expect HKS_ERROR_INVALID_DIGEST
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest001");
    uint32_t wrongDig = 999;
    int32_t ret = HksOpensslHashInit(nullptr, wrongDig);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_DIGEST);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest002
 * @tc.desc: test HksOpensslHashFinal, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest002");
    int32_t ret = HksOpensslHashFinal(nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest003
 * @tc.desc: test HksOpensslHashFinal, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest003");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA256);
    ASSERT_TRUE(ret == HKS_SUCCESS);

    ret = HksOpensslHashFinal(&ctx, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest004
 * @tc.desc: test HksOpensslHashFinal expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest004");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA256);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob msg  = { 0 };
    ret = HksOpensslHashFinal(&ctx, &msg, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest005
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest005");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA224);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest006
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest006");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA1);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest007
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest007");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA384);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest008
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest008");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SHA512);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest009
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest009");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_MD5);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslHashTest.HksFrameworkOpensslHashTest010
 * @tc.desc: test HksOpensslHashInit, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslHashTest, HksFrameworkOpensslHashTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslHashTest010");
    void *ctx = nullptr;
    int32_t ret = HksOpensslHashInit(&ctx, HKS_DIGEST_SM3);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    HksOpensslHashFreeCtx(&ctx);
}
}
