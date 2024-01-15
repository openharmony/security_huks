/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"
#include "file_ex.h"
#include "hks_params_key_data_01.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksUsageSpec usageSpec = {0};
    std::string hexData;
    std::string keyData;
    HksKeySize keySize = HksKeySize::HKS_RSA_KEY_SIZE_512;

    HksErrorCode encryptResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_001_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_001_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000000000000000000000"
        "0000000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_512,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_002_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData =
        "0100000000030000600000006000000060000000eadcc37762c4a0c4cd358de290f2efedf39503a1833e4082aef44cb564ff47d4feaee5"
        "f145b3711cd9abf944e0586bc083dd2c7dde4fc8f7d9a69d4fc5a8aef527c82d02fd30eb33a1791db30011733d60ef3110bd769f385f10"
        "b071ae552dbd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001158f2e62472ec593"
        "4b431f432d0b1ffb37e0f5f45d97d95425bb474f5f760fa1fdbf105c95896358c2a286bf4bd8d20b2d0b0880ff0193bcf0e625a9dbe330"
        "6ea4534c0d7e83b657684194501574a554f76cbe29ce5953e1d92b479b4d1f8201",
    .hexData =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_768,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_003_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_003_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_1024,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_004_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_004_PARAMS_KEY_DATA
    .hexData =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_2048,

#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_005_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_005_PARAMS_KEY_DATA
    .hexData =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_3072,

#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_006_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_006_PARAMS_KEY_DATA
    .hexData =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000",
    .keySize = HKS_RSA_KEY_SIZE_4096,

#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_007_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_007_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_512,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_008_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_008_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_768,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_009_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_009_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_1024,

    .encryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_010_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0010_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_011_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0011_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_ENCRYPT_012_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_0012_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalRsaEncrypt : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown();
    void SetUp();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams) const
    {
        uint32_t keyLen = testCaseParams.keyData.length() / HKS_COUNT_OF_HALF;
        HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        ASSERT_EQ(key.data == nullptr, false) << "key malloc failed.";
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParams.keyData[HKS_COUNT_OF_HALF * ii]);
        }

        uint32_t inLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;
        uint32_t outLen = inLen;
        if (testCaseParams.usageSpec.padding == HKS_PADDING_PKCS1_V1_5) {
            outLen = HKS_KEY_BYTES(testCaseParams.keySize);
        }

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_EQ(message.data == nullptr, false) << "message malloc failed.";
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[HKS_COUNT_OF_HALF * ii]);
        }

        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen + HKS_PADDING_SUPPLENMENT) };
        ASSERT_EQ(cipherText.data == nullptr, false) << "cipherText malloc failed.";
        HksBlob tagAead = { .size = 0, .data = nullptr };

        EXPECT_EQ(HksCryptoHalEncrypt(&key, &testCaseParams.usageSpec, &message, &cipherText, &tagAead),
            testCaseParams.encryptResult);
        HKS_FREE(key.data);
        HKS_FREE(message.data);
        HKS_FREE(cipherText.data);
    }
};

void HksCryptoHalRsaEncrypt::SetUpTestCase(void)
{
}

void HksCryptoHalRsaEncrypt::TearDownTestCase(void)
{
}

void HksCryptoHalRsaEncrypt::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaEncrypt::TearDown()
{
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaEncrypt_001
 * @tc.name      : HksCryptoHalRsaEncrypt_001
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_001, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_002
 * @tc.name      : HksCryptoHalRsaEncrypt_002
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_002, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_003
 * @tc.name      : HksCryptoHalRsaEncrypt_003
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_003, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_003_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_004
 * @tc.name      : HksCryptoHalRsaEncrypt_004
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_004, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_004_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaEncrypt_005
 * @tc.name      : HksCryptoHalRsaEncrypt_005
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_005, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_006
 * @tc.name      : HksCryptoHalRsaEncrypt_006
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-NOPADDING key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_006, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_006_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaEncrypt_007
 * @tc.name      : HksCryptoHalRsaEncrypt_007
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_007, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_008
 * @tc.name      : HksCryptoHalRsaEncrypt_008
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_008, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_009
 * @tc.name      : HksCryptoHalRsaEncrypt_009
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_009, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_009_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_010
 * @tc.name      : HksCryptoHalRsaEncrypt_010
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_010, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_010_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaEncrypt_011
 * @tc.name      : HksCryptoHalRsaEncrypt_011
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_011, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaEncrypt_012
 * @tc.name      : HksCryptoHalRsaEncrypt_012
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-PKCS1Padding key.
 */
HWTEST_F(HksCryptoHalRsaEncrypt, HksCryptoHalRsaEncrypt_012, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_ENCRYPT_012_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS