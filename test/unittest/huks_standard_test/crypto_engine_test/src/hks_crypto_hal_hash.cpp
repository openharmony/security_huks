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
    uint32_t digestAlg = HKS_DIGEST_NONE;
    std::string hexData = "00112233445566778899aabbccddeeff";
    HksErrorCode hashResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_SUPPORT_HASH_C
const TestCaseParams HKS_CRYPTO_HAL_HASH_001_PARAMS = {
    .digestAlg = HKS_DIGEST_SHA256,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_HASH_002_PARAMS = {
    .digestAlg = HKS_DIGEST_SHA384,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_HASH_003_PARAMS = {
    .digestAlg = HKS_DIGEST_SHA512,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};

#if defined(HKS_SUPPORT_SM3_C) && defined(HKS_SUPPORT_HASH_C)
const TestCaseParams HKS_CRYPTO_HAL_HASH_004_PARAMS = {
    .digestAlg = HKS_DIGEST_SM3,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_HASH_005_PARAMS = {
    .digestAlg = HKS_DIGEST_SHA256,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};

#if defined(HKS_SUPPORT_SM3_C) && defined(HKS_SUPPORT_HASH_C)
const TestCaseParams HKS_CRYPTO_HAL_HASH_006_PARAMS = {
    .digestAlg = HKS_DIGEST_SM3,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_HASH_007_PARAMS = {
    .digestAlg = HKS_DIGEST_SHA256,
    .hexData = "",
    .hashResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_HASH_008_PARAMS = {
    .digestAlg = HKS_DIGEST_NONE,
    .hexData = "00112233445566778899aabbccddeeff",
    .hashResult = HKS_ERROR_NOT_SUPPORTED,
};
#endif
}  // namespace

class HksCryptoHalHash : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    uint32_t GetHashSize(uint32_t digestAlg) const
    {
        switch (digestAlg) {
            case HKS_DIGEST_SHA256:
            case HKS_DIGEST_SM3:
                return 32;
            case HKS_DIGEST_SHA384:
                return 48;
            case HKS_DIGEST_SHA512:
                return 64;
            default:
                return 0;
        }
    }

    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        uint32_t hashSize = GetHashSize(testCaseParams.digestAlg);
        if (hashSize == 0 && testCaseParams.hashResult == HKS_SUCCESS) {
            return;
        }

        uint32_t dataLen = testCaseParams.hexData.size() / HKS_COUNT_OF_HALF;
        HksBlob message = { .size = dataLen, .data = nullptr };
        if (dataLen > 0) {
            message.data = (uint8_t *)HksMalloc(dataLen);
            ASSERT_NE(message.data, nullptr);
            for (uint32_t ii = 0; ii < dataLen; ii++) {
                message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
            }
        }

        HksBlob hash = { .size = hashSize, .data = (uint8_t *)HksMalloc(hashSize) };
        ASSERT_NE(hash.data, nullptr);

        EXPECT_EQ(HksCryptoHalHash(testCaseParams.digestAlg, &message, &hash), testCaseParams.hashResult);

        HKS_FREE(hash.data);
        HKS_FREE(message.data);
    }

    void RunTestCaseThreeStage(const TestCaseParams &testCaseParams) const
    {
        uint32_t hashSize = GetHashSize(testCaseParams.digestAlg);
        if (hashSize == 0 && testCaseParams.hashResult == HKS_SUCCESS) {
            return;
        }

        uint32_t dataLen = testCaseParams.hexData.size() / HKS_COUNT_OF_HALF;
        HksBlob message = { .size = dataLen, .data = nullptr };
        if (dataLen > 0) {
            message.data = (uint8_t *)HksMalloc(dataLen);
            ASSERT_NE(message.data, nullptr);
            for (uint32_t ii = 0; ii < dataLen; ii++) {
                message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
            }
        }

        void *ctx = nullptr;
        EXPECT_EQ(HksCryptoHalHashInit(testCaseParams.digestAlg, &ctx), testCaseParams.hashResult);
        if (testCaseParams.hashResult != HKS_SUCCESS) {
            HKS_FREE(message.data);
            return;
        }

        EXPECT_EQ(HksCryptoHalHashUpdate(&message, ctx), testCaseParams.hashResult);
        if (testCaseParams.hashResult != HKS_SUCCESS) {
            HksCryptoHalHashFreeCtx(&ctx);
            HKS_FREE(message.data);
            return;
        }

        uint8_t buff[1] = {0};
        HksBlob finalMessage = { .size = 0, .data = buff };
        HksBlob hash = { .size = hashSize, .data = (uint8_t *)HksMalloc(hashSize) };
        ASSERT_NE(hash.data, nullptr);

        EXPECT_EQ(HksCryptoHalHashFinal(&finalMessage, &ctx, &hash), testCaseParams.hashResult);
        HksCryptoHalHashFreeCtx(&ctx);

        HKS_FREE(hash.data);
        HKS_FREE(message.data);
    }
};

void HksCryptoHalHash::SetUpTestCase(void)
{
}

void HksCryptoHalHash::TearDownTestCase(void)
{
}

void HksCryptoHalHash::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalHash::TearDown()
{
}

#ifdef HKS_SUPPORT_HASH_C
/**
 * @tc.number    : HksCryptoHalHash_001
 * @tc.name      : HksCryptoHalHash_001
 * @tc.desc      : Using HksCryptoHalHash SHA256 one-shot hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalHash_002
 * @tc.name      : HksCryptoHalHash_002
 * @tc.desc      : Using HksCryptoHalHash SHA384 one-shot hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalHash_003
 * @tc.name      : HksCryptoHalHash_003
 * @tc.desc      : Using HksCryptoHalHash SHA512 one-shot hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_003, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_003_PARAMS);
}

#if defined(HKS_SUPPORT_SM3_C) && defined(HKS_SUPPORT_HASH_C)
/**
 * @tc.number    : HksCryptoHalHash_004
 * @tc.name      : HksCryptoHalHash_004
 * @tc.desc      : Using HksCryptoHalHash SM3 one-shot hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_004, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_004_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalHash_005
 * @tc.name      : HksCryptoHalHash_005
 * @tc.desc      : Using HksCryptoHalHashInit/Update/Final SHA256 three-stage hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_005, Function | SmallTest | Level0)
{
    RunTestCaseThreeStage(HKS_CRYPTO_HAL_HASH_005_PARAMS);
}

#if defined(HKS_SUPPORT_SM3_C) && defined(HKS_SUPPORT_HASH_C)
/**
 * @tc.number    : HksCryptoHalHash_006
 * @tc.name      : HksCryptoHalHash_006
 * @tc.desc      : Using HksCryptoHalHashInit/Update/Final SM3 three-stage hash.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_006, Function | SmallTest | Level0)
{
    RunTestCaseThreeStage(HKS_CRYPTO_HAL_HASH_006_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalHash_007
 * @tc.name      : HksCryptoHalHash_007
 * @tc.desc      : Using HksCryptoHalHash SHA256 hash with empty message.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_007, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalHash_008
 * @tc.name      : HksCryptoHalHash_008
 * @tc.desc      : Using HksCryptoHalHash invalid digest NONE.
 */
HWTEST_F(HksCryptoHalHash, HksCryptoHalHash_008, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_HASH_008_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS