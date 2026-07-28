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
    HksUsageSpec usageSpec = {0};
    std::string hexData;

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode encryptResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

const TestCaseParams HKS_CRYPTO_HAL_SM2_ENCRYPT_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_SM2,
        .keyLen = HKS_SM2_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_SM2,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_SM3,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff",

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_ENCRYPT_DECRYPT)
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHalSm2Encrypt : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        HksBlob key = { .size = 0, .data = nullptr };

        EXPECT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);
        if (testCaseParams.generateKeyResult != HKS_SUCCESS) {
            return;
        }

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_NE(message.data, nullptr);
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }

        uint32_t cipherLen = inLen + 65 + 32 + HKS_PADDING_SUPPLENMENT;
        HksBlob cipherText = { .size = cipherLen, .data = (uint8_t *)HksMalloc(cipherLen) };
        ASSERT_NE(cipherText.data, nullptr);
        HksBlob tagAead = { .size = 0, .data = nullptr };

        EXPECT_EQ(HksCryptoHalEncrypt(&key, &testCaseParams.usageSpec, &message, &cipherText, &tagAead),
            testCaseParams.encryptResult);

        HksBlob plainText = { .size = inLen + HKS_PADDING_SUPPLENMENT, .data = (uint8_t *)HksMalloc(inLen + HKS_PADDING_SUPPLENMENT) };
        ASSERT_NE(plainText.data, nullptr);

        EXPECT_EQ(HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &cipherText, &plainText),
            testCaseParams.decryptResult);

        if (testCaseParams.decryptResult == HKS_SUCCESS) {
            EXPECT_EQ(plainText.size, inLen);
            for (uint32_t ii = 0; ii < inLen; ii++) {
                EXPECT_EQ(plainText.data[ii], message.data[ii]);
            }
        }

        HKS_FREE(key.data);
        HKS_FREE(message.data);
        HKS_FREE(cipherText.data);
        HKS_FREE(plainText.data);
    }
};

void HksCryptoHalSm2Encrypt::SetUpTestCase(void)
{
}

void HksCryptoHalSm2Encrypt::TearDownTestCase(void)
{
}

void HksCryptoHalSm2Encrypt::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalSm2Encrypt::TearDown()
{
}

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_ENCRYPT_DECRYPT)
/**
 * @tc.number    : HksCryptoHalSm2Encrypt_001
 * @tc.name      : HksCryptoHalSm2Encrypt_001
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt SM2-256-SM3 key.
 */
HWTEST_F(HksCryptoHalSm2Encrypt, HksCryptoHalSm2Encrypt_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_SM2_ENCRYPT_001_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS