/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <iostream>

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksKeySpec spec = {0};

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
};

const TestCaseParams HKS_CRYPTO_HAL_3DES_KEY_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_3DES,
        .keyLen = HKS_3DES_KEY_SIZE_128,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_3DES_C) && defined(HKS_SUPPORT_3DES_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_3DES_KEY_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_3DES,
        .keyLen = HKS_3DES_KEY_SIZE_192,
        .algParam = nullptr,
    },
#if defined(HKS_SUPPORT_3DES_C) && defined(HKS_SUPPORT_3DES_GENERATE_KEY)
    .generateKeyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHal3DesKey : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        HksBlob keyTest01 = { .size = 0, .data = nullptr };
        ASSERT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &keyTest01), testCaseParams.generateKeyResult);
        if (testCaseParams.generateKeyResult == HKS_SUCCESS) {
            ASSERT_NE((uint32_t)0, keyTest01.size);
            ASSERT_NE(nullptr, keyTest01.data);
            HKS_FREE(keyTest01.data);
        }
    }
};

void HksCryptoHal3DesKey::SetUpTestCase(void)
{
}

void HksCryptoHal3DesKey::TearDownTestCase(void)
{
}

void HksCryptoHal3DesKey::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHal3DesKey::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHal3DesKey_001
 * @tc.name      : HksCryptoHal3DesKey_001
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate 3DES-128bit key.
 */
HWTEST_F(HksCryptoHal3DesKey, HksCryptoHal3DesKey_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_3DES_KEY_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHal3DesKey_002
 * @tc.name      : HksCryptoHal3DesKey_002
 * @tc.desc      : Using HksCryptoHalGenerateKey Generate 3DES-192bit key.
 */
HWTEST_F(HksCryptoHal3DesKey, HksCryptoHal3DesKey_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_3DES_KEY_002_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS