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

#include "hks_openssl_rsa_test.h"

#include <cstring>
#include <gtest/gtest.h>

#include "base/security/huks/frameworks/huks_standard/main/crypto_engine/openssl/src/hks_openssl_rsa.c"
#include "file_ex.h"
#include "hks_openssl_rsa.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksFrameworkRsaEngineTest {
class HksRsaEngineTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksRsaEngineTest::SetUpTestCase(void)
{
}

void HksRsaEngineTest::TearDownTestCase(void)
{
}

void HksRsaEngineTest::SetUp()
{
}

void HksRsaEngineTest::TearDown()
{
}

/**
 * @tc.name: HksRsaEngineTest.HksRsaEngineTest001
 * @tc.desc: tdd HksRsaEngineTest001, function is RsaGenKeyCheckParam
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaEngineTest, HksRsaEngineTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksRsaEngineTest001");
    HksKeySpec spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    };
    int32_t ret = RsaGenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest001 failed, ret = " << ret;

    spec.keyLen = HKS_RSA_KEY_SIZE_1024;
    ret = RsaGenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest001 failed, ret = " << ret;

    spec.keyLen = HKS_RSA_KEY_SIZE_2048;
    ret = RsaGenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest001 failed, ret = " << ret;

    spec.keyLen = HKS_RSA_KEY_SIZE_3072;
    ret = RsaGenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest001 failed, ret = " << ret;

    spec.keyLen = HKS_RSA_KEY_SIZE_4096;
    ret = RsaGenKeyCheckParam(&spec);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksRsaEngineTest.HksRsaEngineTest002
 * @tc.desc: tdd HksRsaEngineTest002, function is RsaCheckKeyMaterial
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaEngineTest, HksRsaEngineTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksRsaEngineTest002");
    KeyMaterialRsa data = {
        .keyAlg = HKS_ALG_RSA,
        .keySize = 1024,
        .nSize = 20,
        .eSize = 20,
        .dSize = 20,
    };

    HksBlob key = {
        .size = 64,
        .data = (uint8_t *)&data,
    };

    int32_t ret = RsaCheckKeyMaterial(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksRsaEngineTest002 failed, ret = " << ret;

    ret = RsaCheckKeyMaterial(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksRsaEngineTest002 failed, ret = " << ret;

    ret = RsaCheckKeyMaterial(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksRsaEngineTest002 failed, ret = " << ret;

    ret = RsaCheckKeyMaterial(&key);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksRsaEngineTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksRsaEngineTest.HksRsaEngineTest003
 * @tc.desc: tdd HksRsaEngineTest003, function is GetRsaCryptPadding
 * @tc.type: FUNC
 */
HWTEST_F(HksRsaEngineTest, HksRsaEngineTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksRsaEngineTest003");
    uint32_t inPadding = HKS_PADDING_NONE;
    uint32_t outPadding = 0;
    int32_t ret = GetRsaCryptPadding(inPadding, &outPadding);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksRsaEngineTest003 failed, ret = " << ret;

    inPadding = 99;
    ret = GetRsaCryptPadding(inPadding, &outPadding);
    ASSERT_EQ(ret, HKS_ERROR_NOT_SUPPORTED) << "HksRsaEngineTest003 failed, ret = " << ret;
}
}