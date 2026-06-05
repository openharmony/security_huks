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
#include "hks_log.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksKeySpec spec = {0};
    HksUsageSpec usageSpec = {0};
    HksStageType runStage = HksStageType::HKS_STAGE_THREE;

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode signResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode verifyResult = HksErrorCode::HKS_SUCCESS;
};

const uint32_t SIGNATURE_SIZE = 128;
const uint32_t MAX_PUB_KEY_SIZE = 218;

const TestCaseParams HKS_CRYPTO_HAL_SM2_SIGN_001_PARAMS = {
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
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .runStage = HksStageType::HKS_STAGE_THREE,

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_SIGN_VERIFY)
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
    .signResult = HKS_ERROR_NOT_SUPPORTED,
    .verifyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_SM2_SIGN_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_SM2,
        .keyLen = HKS_SM2_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_SM2,
        .mode = 0,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .runStage = HksStageType::HKS_STAGE_TWO,

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_SIGN_VERIFY)
    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
#else
    .generateKeyResult = HKS_ERROR_NOT_SUPPORTED,
    .signResult = HKS_ERROR_NOT_SUPPORTED,
    .verifyResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
}  // namespace

class HksCryptoHalSm2Sign : public HksCryptoHalCommon, public testing::Test {
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

        const char *hexData = "00112233445566778899aabbccddeeff";
        uint32_t dataLen = strlen(hexData) / HKS_COUNT_OF_HALF;

        HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
        ASSERT_NE(message.data, nullptr);
        for (uint32_t ii = 0; ii < dataLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&hexData[HKS_COUNT_OF_HALF * ii]);
        }

        struct HksBlob* pBlob = nullptr;
        uint8_t hashData[HKS_HMAC_DIGEST_SHA512_LEN] = {0};
        struct HksBlob hash = { HKS_HMAC_DIGEST_SHA512_LEN, hashData };
        struct HksUsageSpec usageSpecTmp = testCaseParams.usageSpec;
        if (testCaseParams.runStage == HksStageType::HKS_STAGE_THREE) {
            uint32_t inputDigest = usageSpecTmp.digest;
            usageSpecTmp.digest = (inputDigest == HKS_DIGEST_NONE) ? HKS_DIGEST_SM3 : inputDigest;
            EXPECT_EQ(HksCryptoHalHash(usageSpecTmp.digest, &message, &hash), HKS_SUCCESS);
            pBlob = &hash;
        } else {
            pBlob = &message;
        }

        struct HksBlob signature = { .size = SIGNATURE_SIZE, .data = (uint8_t *)HksMalloc(SIGNATURE_SIZE) };
        ASSERT_NE(signature.data, nullptr);

        EXPECT_EQ(HksCryptoHalSign(&key, &usageSpecTmp, pBlob, &signature), testCaseParams.signResult);

        struct HksBlob pubKey = { .size = MAX_PUB_KEY_SIZE, .data = (uint8_t *)HksMalloc(MAX_PUB_KEY_SIZE) };
        ASSERT_NE(pubKey.data, nullptr);

        EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

        EXPECT_EQ(
            HksCryptoHalVerify(&pubKey, &usageSpecTmp, pBlob, &signature), testCaseParams.verifyResult);

        HKS_FREE(message.data);
        HKS_FREE(signature.data);
        HKS_FREE(pubKey.data);
        HKS_FREE(key.data);
    }
};

void HksCryptoHalSm2Sign::SetUpTestCase(void)
{
}

void HksCryptoHalSm2Sign::TearDownTestCase(void)
{
}

void HksCryptoHalSm2Sign::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalSm2Sign::TearDown()
{
}

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM2_SIGN_VERIFY)
/**
 * @tc.number    : HksCryptoHalSm2Sign_001
 * @tc.name      : HksCryptoHalSm2Sign_001
 * @tc.desc      : Using HksCryptoHalSign Sign SM2-256-SM3 key.
 */
HWTEST_F(HksCryptoHalSm2Sign, HksCryptoHalSm2Sign_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_SM2_SIGN_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalSm2Sign_002
 * @tc.name      : HksCryptoHalSm2Sign_002
 * @tc.desc      : Using HksCryptoHalSign Sign SM2-256-NONE key.
 */
HWTEST_F(HksCryptoHalSm2Sign, HksCryptoHalSm2Sign_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_SM2_SIGN_002_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS