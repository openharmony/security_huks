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
#include "base/security/huks/frameworks/huks_standard/main/crypto_engine/openssl/src/hks_openssl_sm4.c"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_aes.h"
#include "hks_param.h"

#include <openssl/evp.h>
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
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
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
    int32_t ret = HksInitialize();
    ASSERT_TRUE(ret == HKS_SUCCESS);
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
    HksOpensslSm4HalFreeCtx(reinterpret_cast<void **>(&opensslSm4Ctx));
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test007
 * @tc.desc: test function Sm4GenKeyCheckParam
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test007, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test007");
    HksKeySpec spec = {
        .algType = 0,
        .keyLen = 0,
        .algParam = nullptr,
    };
    int32_t ret = Sm4GenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test007 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test008
 * @tc.desc: test function GetSm4CbcCipherType
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test008, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test008");
    const EVP_CIPHER *ret = GetSm4CipherType(0, HKS_MODE_CBC);
    ASSERT_EQ(ret, nullptr) << "HksFrameworkOpensslSm4Test008 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test009
 * @tc.desc: test function GetSm4CtrCipherType
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test009, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test009");
    const EVP_CIPHER *ret = GetSm4CipherType(0, HKS_MODE_CTR);
    ASSERT_EQ(ret, nullptr) << "HksFrameworkOpensslSm4Test009 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test010
 * @tc.desc: test function GetSm4EcbCipherType
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test010, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test010");
    const EVP_CIPHER *ret = GetSm4CipherType(0, HKS_MODE_ECB);
    ASSERT_EQ(ret, nullptr) << "HksFrameworkOpensslSm4Test010 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test011
 * @tc.desc: test function HksOpensslSm4EncryptInit and HksOpensslSm4DecryptInit
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test011, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test011");
    HksUsageSpec spec = {
        .mode = 0,
    };
    int32_t ret = HksOpensslSm4EncryptInit(nullptr, nullptr, &spec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test011 failed, ret = " << ret;

    ret = HksOpensslSm4DecryptInit(nullptr, nullptr, &spec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test011 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test012
 * @tc.desc: test function HksOpensslSm4EncryptUpdate and HksOpensslSm4DecryptUpdate
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test012, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test012");
    HksOpensslBlockCipherCtx ctx = {
        .mode = 0,
    };
    int32_t ret = HksOpensslSm4EncryptUpdate(reinterpret_cast<void *>(&ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test012 failed, ret = " << ret;

    ret = HksOpensslSm4DecryptUpdate(reinterpret_cast<void *>(&ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test012 failed, ret = " << ret;
}

/**
 * @tc.name: HksFrameworkOpensslSm4Test.HksFrameworkOpensslSm4Test013
 * @tc.desc: test function HksOpensslSm4EncryptFinal
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslSm4Test, HksFrameworkOpensslSm4Test013, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslSm4Test013");
    HksUsageSpec *spec = reinterpret_cast<HksUsageSpec *>(HksMalloc(sizeof(HksUsageSpec)));
    ASSERT_NE(spec, nullptr);
    spec->mode = 0;
    int32_t ret = HksOpensslSm4EncryptFinal(reinterpret_cast<void **>(&spec), nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test013 failed, ret = " << ret;

    ret = HksOpensslSm4DecryptFinal(reinterpret_cast<void **>(&spec), nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksFrameworkOpensslSm4Test013 failed, ret = " << ret;
}

}