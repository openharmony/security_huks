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

#include "hks_openssl_sm4_test.h"

#include <gtest/gtest.h>

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_openssl_sm4.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_aes.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkOpensslSm4Test {
class HksFrameworkOpensslSm4Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkOpensslSm4Test::SetUpTestCase(void)
{
}

void HksFrameworkOpensslSm4Test::TearDownTestCase(void)
{
}

void HksFrameworkOpensslSm4Test::SetUp()
{
}

void HksFrameworkOpensslSm4Test::TearDown()
{
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test001
 * @tc.desc: test HksOpensslSm4HalFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test001");
    HksOpensslSm4HalFreeCtx(nullptr);
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test002
 * @tc.desc: test HksOpensslSm4HalFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test002");
    void *ctx = nullptr;
    HksOpensslSm4HalFreeCtx(&ctx);
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test003
 * @tc.desc: test HksOpensslSm4HalFreeCtx with HKS_MODE_CBC
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test003");
    HksOpensslBlockCipherCtx *opensslSm4Ctx =
        reinterpret_cast<HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_NE(opensslSm4Ctx, nullptr);
    opensslSm4Ctx->mode = HKS_MODE_CBC;
    opensslSm4Ctx->append = nullptr;
    HksOpensslSm4HalFreeCtx(reinterpret_cast<void **>(&opensslSm4Ctx));
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test004
 * @tc.desc: test HksOpensslSm4HalFreeCtx with HKS_MODE_CTR
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test004, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test004");
    HksOpensslBlockCipherCtx *opensslSm4Ctx =
        reinterpret_cast<HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_NE(opensslSm4Ctx, nullptr);
    opensslSm4Ctx->mode = HKS_MODE_CTR;
    opensslSm4Ctx->append = nullptr;
    HksOpensslSm4HalFreeCtx(reinterpret_cast<void **>(&opensslSm4Ctx));}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test005
 * @tc.desc: test HksOpensslSm4HalFreeCtx with HKS_MODE_ECB
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test005, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test005");
    HksOpensslBlockCipherCtx *opensslSm4Ctx =
        reinterpret_cast<HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_NE(opensslSm4Ctx, nullptr);
    opensslSm4Ctx->mode = HKS_MODE_ECB;
    opensslSm4Ctx->append = nullptr;
    HksOpensslSm4HalFreeCtx(reinterpret_cast<void **>(&opensslSm4Ctx));}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test006
 * @tc.desc: test HksOpensslSm4HalFreeCtx with HKS_MODE_GCM
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test006, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test006");
    HksOpensslBlockCipherCtx *opensslSm4Ctx =
        reinterpret_cast<HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_NE(opensslSm4Ctx, nullptr);
    opensslSm4Ctx->mode = HKS_MODE_GCM;
    opensslSm4Ctx->append = nullptr;
    HksOpensslSm4HalFreeCtx(reinterpret_cast<void **>(&opensslSm4Ctx));}
}
