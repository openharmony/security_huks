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

#include "hks_openssl_hmac_test.h"

#include <cstring>
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "file_ex.h"
#include "hks_openssl_hmac.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksFrameworkHmacEngineTest {
class HksHmacEngineTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksHmacEngineTest::SetUpTestCase(void)
{
}

void HksHmacEngineTest::TearDownTestCase(void)
{
}

void HksHmacEngineTest::SetUp()
{
}

void HksHmacEngineTest::TearDown()
{
}

/**
 * @tc.name: HksHmacEngineTest.HksHmacEngineTest001
 * @tc.desc: tdd HksHmacEngineTest001, function is HksOpensslHmacFinal
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacEngineTest, HksHmacEngineTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksHmacEngineTest001");
    int32_t ret = HksOpensslHmacFinal(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksHmacEngineTest001 failed, ret = " << ret;
    void *crypto = nullptr;
    ret = HksOpensslHmacFinal(&crypto, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_NULL_POINTER) << "HksHmacEngineTest001 failed, ret = " << ret;

    struct HksOpensslHmacCtx *hmacCtx =
        reinterpret_cast<struct HksOpensslHmacCtx *>(HksMalloc(sizeof(struct HksOpensslHmacCtx)));
    ASSERT_EQ(hmacCtx == nullptr, false) << "ctx malloc failed.";
    hmacCtx->append = nullptr;
    ret = HksOpensslHmacFinal(reinterpret_cast<void **>(&hmacCtx), nullptr, nullptr);
    ASSERT_EQ(ret, HKS_FAILURE) << "HksHmacEngineTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksHmacEngineTest.HksHmacEngineTest002
 * @tc.desc: tdd HksHmacEngineTest002, function is HksOpensslHmacHalFreeCtx
 * @tc.type: FUNC
 */
HWTEST_F(HksHmacEngineTest, HksHmacEngineTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksHmacEngineTest002");
    void **ptr = nullptr;
    HksOpensslHmacHalFreeCtx(ptr);

    void *ptrTwo = nullptr;
    HksOpensslHmacHalFreeCtx(reinterpret_cast<void **>(&ptrTwo));

    struct HksOpensslHmacCtx *hmacCtx =
        reinterpret_cast<struct HksOpensslHmacCtx *>(HksMalloc(sizeof(struct HksOpensslHmacCtx)));
    ASSERT_EQ(hmacCtx == nullptr, false) << "ctx malloc failed.";
    hmacCtx->digestLen = HKS_ALG_AES;
    hmacCtx->append = nullptr;
    HksOpensslHmacHalFreeCtx(reinterpret_cast<void **>(&hmacCtx));
}

}