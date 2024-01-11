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

#include "hks_openssl_aes_test.h"

#include <cstring>
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "file_ex.h"
#include "hks_openssl_aes.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksFrameworkAesEngineTest {
class HksAesEngineTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksAesEngineTest::SetUpTestCase(void)
{
}

void HksAesEngineTest::TearDownTestCase(void)
{
}

void HksAesEngineTest::SetUp()
{
}

void HksAesEngineTest::TearDown()
{
}

/**
 * @tc.name: HksAesEngineTest.HksAesEngineTest001
 * @tc.desc: tdd HksAesEngineTest001, function is HksOpensslAesXxxxxInit, mode = HKS_MODE_ECB and HKS_MODE_CTR
 * @tc.type: FUNC
 */
HWTEST_F(HksAesEngineTest, HksAesEngineTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksAesEngineTest001");
    const uint32_t dataSize = 1024;
    void* encryptCtx = reinterpret_cast<void *>(HksMalloc(dataSize));
    ASSERT_EQ(encryptCtx == nullptr, false) << "encryptCtx malloc failed.";
    HksBlob key = { .size = 0, .data = nullptr };
    // test HKS_MODE_ECB mode
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };
    int32_t ret = HksOpensslAesEncryptInit(&encryptCtx, &key, &usageSpec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest001 failed, ret = " << ret;

    ret = HksOpensslAesDecryptInit(&encryptCtx, &key, &usageSpec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest001 failed, ret = " << ret;

    // test HKS_MODE_CTR mode
    usageSpec.mode = HKS_MODE_CTR;
    ret = HksOpensslAesEncryptInit(&encryptCtx, &key, &usageSpec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest001 failed, ret = " << ret;
    ret = HksOpensslAesDecryptInit(&encryptCtx, &key, &usageSpec);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest001 failed, ret = " << ret;
    HKS_FREE(encryptCtx);
}

/**
 * @tc.name: HksAesEngineTest.HksAesEngineTest002
 * @tc.desc: tdd HksAesEngineTest002, function is HksOpensslAesXxxxxUpdate, mode = HKS_MODE_ECB and HKS_MODE_CTR
 * @tc.type: FUNC
 */
HWTEST_F(HksAesEngineTest, HksAesEngineTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksAesEngineTest002");
    struct HksOpensslBlockCipherCtx *ctx =
        reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->algType = HKS_ALG_AES;
    ctx->mode = HKS_MODE_ECB;
    ctx->padding = HKS_PADDING_NONE;
    ctx->append = nullptr;

    int32_t ret = HksOpensslAesEncryptUpdate(reinterpret_cast<void *>(ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest002 failed, ret = " << ret;

    ret = HksOpensslAesDecryptUpdate(reinterpret_cast<void *>(ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest002 failed, ret = " << ret;

    // test HKS_MODE_CTR mode
    ctx->mode = HKS_MODE_CTR;
    ret = HksOpensslAesEncryptUpdate(reinterpret_cast<void *>(ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest002 failed, ret = " << ret;
    ret = HksOpensslAesDecryptUpdate(reinterpret_cast<void *>(ctx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest002 failed, ret = " << ret;
    HKS_FREE(ctx);
}

/**
 * @tc.name: HksAesEngineTest.HksAesEngineTest003
 * @tc.desc: tdd HksAesEngineTest003, function is HksOpensslAesXxxxxFinal, mode = HKS_MODE_ECB, HKS_MODE_CTR and 0
 * @tc.type: FUNC
 */
HWTEST_F(HksAesEngineTest, HksAesEngineTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksAesEngineTest003");
    struct HksOpensslBlockCipherCtx *ctx =
        reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = HKS_MODE_ECB;
    ctx->append = nullptr;

    HksBlob* data = nullptr;

    int32_t ret = HksOpensslAesEncryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest003 failed, ret = " << ret;

    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = HKS_MODE_ECB;
    ctx->append = nullptr;
    ret = HksOpensslAesDecryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest003 failed, ret = " << ret;

    // test HKS_MODE_CTR mode
    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = HKS_MODE_CTR;
    ctx->append = nullptr;
    ret = HksOpensslAesEncryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest003 failed, ret = " << ret;

    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = HKS_MODE_CTR;
    ctx->append = nullptr;
    ret = HksOpensslAesDecryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksAesEngineTest003 failed, ret = " << ret;

    // test invalid mode 0
    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = 0;
    ctx->append = nullptr;
    ret = HksOpensslAesEncryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest003 failed, ret = " << ret;
    ret = HksOpensslAesDecryptFinal(reinterpret_cast<void **>(&ctx), data, data, data);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest003 failed, ret = " << ret;
    HKS_FREE(ctx);
}

/**
 * @tc.name: HksAesEngineTest.HksAesEngineTest004
 * @tc.desc: tdd HksAesEngineTest004, function is HksOpensslAesHalFreeCtx, mode = HKS_MODE_ECB, HKS_MODE_CTR and 0
 * @tc.type: FUNC
 */
HWTEST_F(HksAesEngineTest, HksAesEngineTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksAesEngineTest004");

    void **ptr = nullptr;
    HksOpensslAesHalFreeCtx(ptr);

    void *ptrTwo = nullptr;
    HksOpensslAesHalFreeCtx(reinterpret_cast<void **>(&ptrTwo));

    struct HksOpensslBlockCipherCtx *ctx =
        reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    // test HKS_MODE_ECB mode
    ctx->mode = HKS_MODE_ECB;
    ctx->append = nullptr;

    HksOpensslAesHalFreeCtx(reinterpret_cast<void **>(&ctx));

    // test HKS_MODE_CTR mode and append is not null
    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    ctx->mode = HKS_MODE_CTR;
    EVP_CIPHER_CTX *EvpCtx = EVP_CIPHER_CTX_new();
    ASSERT_EQ(EvpCtx == nullptr, false) << "EvpCtx malloc failed.";
    ctx->append = reinterpret_cast<void *>(EvpCtx);
    HksOpensslAesHalFreeCtx(reinterpret_cast<void **>(&ctx));

    // test HKS_MODE_GCM mode and append is not null
    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    ctx->mode = HKS_MODE_GCM;
    EvpCtx = EVP_CIPHER_CTX_new();
    ASSERT_EQ(EvpCtx == nullptr, false) << "EvpCtx malloc failed.";
    ctx->append = reinterpret_cast<void *>(EvpCtx);
    HksOpensslAesHalFreeCtx(reinterpret_cast<void **>(&ctx));

    // test invalid mode 0
    ctx = reinterpret_cast<struct HksOpensslBlockCipherCtx *>(HksMalloc(sizeof(HksOpensslBlockCipherCtx)));
    ASSERT_EQ(ctx == nullptr, false) << "ctx malloc failed.";
    ctx->mode = 0;
    HksOpensslAesHalFreeCtx(reinterpret_cast<void **>(&ctx));
}

/**
 * @tc.name: HksAesEngineTest.HksAesEngineTest005
 * @tc.desc: tdd HksAesEngineTest005, function is HksOpensslAesEncrypt or HksOpensslAesDecrypt
 * @tc.type: FUNC
 */
HWTEST_F(HksAesEngineTest, HksAesEngineTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksAesEngineTest005");
    HksBlob key = { .size = 0, .data = nullptr };
    HksBlob cioherText = { .size = 0, .data = nullptr };
    // test HKS_MODE_ECB mode
    HksUsageSpec usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    };
    int32_t ret = HksOpensslAesEncrypt(&key, &usageSpec, nullptr, &cioherText, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest005 failed, ret = " << ret;

    ret = HksOpensslAesDecrypt(&key, &usageSpec, nullptr, &cioherText);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest005 failed, ret = " << ret;

    // test HKS_MODE_CTR mode
    usageSpec.mode = HKS_MODE_CTR;
    ret = HksOpensslAesEncrypt(&key, &usageSpec, nullptr, &cioherText, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest005 failed, ret = " << ret;

    ret = HksOpensslAesDecrypt(&key, &usageSpec, nullptr, &cioherText);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksAesEngineTest005 failed, ret = " << ret;
}

}