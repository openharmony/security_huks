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
    HksErrorCode deriveResult = HksErrorCode::HKS_SUCCESS;
};

const std::string g_hexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#ifdef HKS_SUPPORT_KDF_HKDF
const TestCaseParams HKS_CRYPTO_HAL_KDF_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_HKDF,
        .keyLen = HKS_KEY_BYTES(256),
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_KDF_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_HKDF,
        .keyLen = HKS_KEY_BYTES(384),
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_KDF_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_HKDF,
        .keyLen = HKS_KEY_BYTES(512),
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};
#endif

#ifdef HKS_SUPPORT_KDF_PBKDF2
const TestCaseParams HKS_CRYPTO_HAL_KDF_004_PARAMS = {
    .spec = {
        .algType = HKS_ALG_PBKDF2,
        .keyLen = HKS_KEY_BYTES(256),
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};
#endif

#if defined(HKS_SUPPORT_SM3_C) && defined(_USE_OPENSSL_)
const TestCaseParams HKS_CRYPTO_HAL_KDF_005_PARAMS = {
    .spec = {
        .algType = HKS_ALG_GMKDF,
        .keyLen = HKS_KEY_BYTES(HKS_SM4_KEY_SIZE_128),
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_KDF_006_PARAMS = {
    .spec = {
        .algType = HKS_ALG_GMKDF,
        .keyLen = 19,
        .algParam = nullptr,
    },
    .deriveResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_KDF_007_PARAMS = {
    .spec = {0},
    .deriveResult = HKS_ERROR_INVALID_ARGUMENT,
};
}  // namespace

class HksCryptoHalKdf : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void BuildDerivationParam(const TestCaseParams &testCaseParams, struct HksKeyDerivationParam &derParam) const
    {
        std::string hexSalt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        uint32_t saltLen = hexSalt.size() / HKS_COUNT_OF_HALF;
        derParam.salt = { .size = saltLen, .data = (uint8_t *)HksMalloc(saltLen) };
        if (derParam.salt.data != nullptr) {
            for (uint32_t ii = 0; ii < saltLen; ii++) {
                derParam.salt.data[ii] = ReadHex((const uint8_t *)&hexSalt[HKS_COUNT_OF_HALF * ii]);
            }
        }

        derParam.info = { .size = strlen("The factor1"), .data = (uint8_t *)"The factor1" };

        if (testCaseParams.spec.algType == HKS_ALG_PBKDF2) {
            derParam.iterations = 1000;
            derParam.digestAlg = HKS_DIGEST_SHA256;
        } else if (testCaseParams.spec.algType == HKS_ALG_HKDF) {
            derParam.iterations = 0;
            derParam.digestAlg = HKS_DIGEST_SHA256;
        } else if (testCaseParams.spec.algType == HKS_ALG_GMKDF) {
            derParam.iterations = 0;
            derParam.digestAlg = HKS_DIGEST_SM3;
        } else {
            derParam.iterations = 0;
            derParam.digestAlg = HKS_DIGEST_SHA256;
        }
    }

    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        if (testCaseParams.spec.algType == 0 && testCaseParams.deriveResult == HKS_ERROR_INVALID_ARGUMENT) {
            HksBlob mainKey = { .size = 0, .data = nullptr };
            HksBlob derivedKey = { .size = 0, .data = nullptr };
            EXPECT_EQ(HksCryptoHalDeriveKey(&mainKey, nullptr, &derivedKey), testCaseParams.deriveResult);
            return;
        }

        uint32_t keyLen = g_hexKey.size() / HKS_COUNT_OF_HALF;
        HksBlob mainKey = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        ASSERT_NE(mainKey.data, nullptr);
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            mainKey.data[ii] = ReadHex((const uint8_t *)&g_hexKey[HKS_COUNT_OF_HALF * ii]);
        }

        HksKeySpec spec = testCaseParams.spec;
        struct HksKeyDerivationParam derParam = {0};
        BuildDerivationParam(testCaseParams, derParam);
        spec.algParam = &derParam;

        HksBlob derivedKey = { .size = spec.keyLen, .data = (uint8_t *)HksMalloc(spec.keyLen) };
        ASSERT_NE(derivedKey.data, nullptr);

        EXPECT_EQ(HksCryptoHalDeriveKey(&mainKey, &spec, &derivedKey), testCaseParams.deriveResult);

        HKS_FREE(derParam.salt.data);
        HKS_FREE(derivedKey.data);
        HKS_FREE(mainKey.data);
    }
};

void HksCryptoHalKdf::SetUpTestCase(void)
{
}

void HksCryptoHalKdf::TearDownTestCase(void)
{
}

void HksCryptoHalKdf::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalKdf::TearDown()
{
}

#ifdef HKS_SUPPORT_KDF_HKDF
/**
 * @tc.number    : HksCryptoHalKdf_001
 * @tc.name      : HksCryptoHalKdf_001
 * @tc.desc      : Using HksCryptoHalDeriveKey HKDF-SHA256 derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalKdf_002
 * @tc.name      : HksCryptoHalKdf_002
 * @tc.desc      : Using HksCryptoHalDeriveKey HKDF-SHA384 derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalKdf_003
 * @tc.name      : HksCryptoHalKdf_003
 * @tc.desc      : Using HksCryptoHalDeriveKey HKDF-SHA512 derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_003, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_003_PARAMS);
}
#endif

#ifdef HKS_SUPPORT_KDF_PBKDF2
/**
 * @tc.number    : HksCryptoHalKdf_004
 * @tc.name      : HksCryptoHalKdf_004
 * @tc.desc      : Using HksCryptoHalDeriveKey PBKDF2-SHA256 derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_004, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_004_PARAMS);
}
#endif

#if defined(HKS_SUPPORT_SM3_C) && defined(_USE_OPENSSL_)
/**
 * @tc.number    : HksCryptoHalKdf_005
 * @tc.name      : HksCryptoHalKdf_005
 * @tc.desc      : Using HksCryptoHalDeriveKey SM3KDF derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_005, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalKdf_006
 * @tc.name      : HksCryptoHalKdf_006
 * @tc.desc      : Using HksCryptoHalDeriveKey SM3KDF partial block derive key.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_006, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_006_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalKdf_007
 * @tc.name      : HksCryptoHalKdf_007
 * @tc.desc      : Using HksCryptoHalDeriveKey null spec negative test.
 */
HWTEST_F(HksCryptoHalKdf, HksCryptoHalKdf_007, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_KDF_007_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS