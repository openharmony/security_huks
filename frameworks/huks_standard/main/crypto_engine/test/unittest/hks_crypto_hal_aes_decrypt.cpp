/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <string>
#include <memory>

#include <gtest/gtest.h>

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
    HksUsageSpec usageSpec;
    std::string keyData;
    std::string hexData;

    HksErrorCode decryptResult;
};
struct TestCaseParamsForGcm {
    std::string keyData;
    std::string hexData;
    std::string tagDec;

    HksErrorCode decryptResult;
};

uint8_t IV[16] = {0};
HksCipherParam tagIv = { .iv = { .size = 16, .data = IV } };

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_001_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "2665c033ca1d760d7fcfffce8eb09356a6a6e508584af3faf82fcce81b758934",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_002_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "6b6579306b6579306b6579306b657930",
    .hexData = "a043f74ce2620fc939811e9a949e9f0576c60fb964670ed6e626260f7e6d972aca0d0aeff876a8f03fd8ed8b91ff3f9a",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_003_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "2665c033ca1d760d7fcfffce8eb09356a6a6e508584af3faf82fcce81b758934",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_004_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "2665c033ca1d760d7fcfffce8eb09356",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_005_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "2665c033ca1d760d7fcfffce8eb0935670f5531be24753f04e3200829ea2fd60",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParamsForGcm HKS_CRYPTO_HAL_AES_DECRYPT_006_PARAMS = {
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "fd692103d931c663a0371bd250dd883aed48379774bfba64327cc4a3ea19afae",
    .tagDec = "43a345ff5f3af4bb383f999393949acc",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_007_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "6b5d0d7ac2df878c338f085edf3431116b5d0d7ac2df878c338f085edf343111",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_008_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "6b6579306b6579306b6579306b6579306b6579306b657930",
    .hexData = "7897f888bda5244c049da27f1533dc80accf7a0c8a9169fa64779d1f34be146dcb0f793048dee9efaa032c7901b07b64",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_009_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "6b5d0d7ac2df878c338f085edf3431116b5d0d7ac2df878c338f085edf343111",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_010_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "6b5d0d7ac2df878c338f085edf343111",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_011_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "6b5d0d7ac2df878c338f085edf343111cf0afb8fc67acf62db781f324ecc361c",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParamsForGcm HKS_CRYPTO_HAL_AES_DECRYPT_012_PARAMS = {
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "06c34934467ad390f5f54410ac20c875feda920d514c3e43819ce16e1e2e3335",
    .tagDec = "b3ad99cd7951405f1eeefb4e54783f17",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_013_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "f905f3936288181cb1d3931ab26c0314056d1521dc8549013a9b829bebedc71b",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_014_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "6b6579306b6579306b6579306b6579306b6579306b6579306b6579306b657930",
    .hexData = "acec21f1488248cdcf6f24a15124b1a68e401efd146cd944fabd84081b76dacf89989a52f8fc1e31dacb820ec8102365",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_015_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "f905f3936288181cb1d3931ab26c0314056d1521dc8549013a9b829bebedc71b",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_016_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "f905f3936288181cb1d3931ab26c0314",

    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_DECRYPT_017_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "6b6579306b6579306b6579306b6579306b6579306b6579306b6579306b657930",
    .hexData = "776a9f622d0978f89fff5c61ae5d4693776a9f622d0978f89fff5c61ae5d469379ea9dc7d7419ec0ea457aa041e1007a",
#if defined(_USE_OPENSSL_)
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .decryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParamsForGcm HKS_CRYPTO_HAL_AES_DECRYPT_018_PARAMS = {
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "da047651955c64daa5cac9b0082f1567235e682041061fef12f896ba83bb1fde",
    .tagDec = "35a956a070d5ed7472a9b66165bcada7",

    .decryptResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalAesDecrypt : public HksCryptoHalCommon, public testing::Test {
protected:
    void RunTestCase(const TestCaseParams &testCaseParams)
    {
        uint32_t keyLen = testCaseParams.keyData.length() / 2;
        HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParams.keyData[2 * ii]);
        }
        uint32_t inLen = testCaseParams.hexData.length() / 2;
        uint32_t outLen = inLen;
        if (testCaseParams.usageSpec.padding == HKS_PADDING_PKCS7) {
            outLen = (inLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;
        }
        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[2 * ii]);
        }
        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen + HKS_PADDING_SUPPLENMENT) };
        EXPECT_EQ(
            HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &message, &cipherText), testCaseParams.decryptResult);
        HksFree(key.data);
        HksFree(message.data);
        HksFree(cipherText.data);
    }

    void GcmRunTestCase(const TestCaseParamsForGcm &testCaseParamsForGcm)
    {
        uint32_t keyLen = testCaseParamsForGcm.keyData.length() / 2;
        HksBlob key = { .size = keyLen, .data = (uint8_t *)HksMalloc(keyLen) };
        for (uint32_t ii = 0; ii < keyLen; ii++) {
            key.data[ii] = ReadHex((const uint8_t *)&testCaseParamsForGcm.keyData[2 * ii]);
        }
        uint32_t inLen = testCaseParamsForGcm.hexData.length() / 2;
        uint32_t outLen = inLen;
        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParamsForGcm.hexData[2 * ii]);
        }
        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen + HKS_PADDING_SUPPLENMENT) };
        uint32_t tagDecSize = testCaseParamsForGcm.tagDec.length() / 2;
        HksBlob tagDecBlob = { .size = tagDecSize, .data = (uint8_t *)HksMalloc(tagDecSize) };
        for (uint32_t ii = 0; ii < tagDecSize; ii++) {
            tagDecBlob.data[ii] = ReadHex((const uint8_t *)&testCaseParamsForGcm.tagDec[2 * ii]);
        }
        HksAeadParam aeadParam = {
            .nonce = { .size = 16, .data = IV },
            .aad = { .size = 0, .data = nullptr },
            .tagDec = tagDecBlob,
            .payloadLen = 0,
        };
        HksUsageSpec usageSpec = {
            .algType = HKS_ALG_AES,
            .mode = HKS_MODE_GCM,
            .padding = HKS_PADDING_NONE,
            .digest = HKS_DIGEST_NONE,
            .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            .algParam = &aeadParam,
        };
        EXPECT_EQ(HksCryptoHalDecrypt(&key, &usageSpec, &message, &cipherText), testCaseParamsForGcm.decryptResult);
        HksFree(key.data);
        HksFree(message.data);
        HksFree(cipherText.data);
        HksFree(tagDecBlob.data);
    }
};

/**
 * @tc.number    : HksCryptoHalAesDecrypt_001
 * @tc.name      : HksCryptoHalAesDecrypt_001
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_002
 * @tc.name      : HksCryptoHalAesDecrypt_002
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_003
 * @tc.name      : HksCryptoHalAesDecrypt_003
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_003, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_003_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_004
 * @tc.name      : HksCryptoHalAesDecrypt_004
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_004, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_004_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_005
 * @tc.name      : HksCryptoHalAesDecrypt_005
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_005, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_006
 * @tc.name      : HksCryptoHalAesDecrypt_006
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-128-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_006, Function | SmallTest | Level0)
{
    GcmRunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_006_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_007
 * @tc.name      : HksCryptoHalAesDecrypt_007
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_007, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_008
 * @tc.name      : HksCryptoHalAesDecrypt_008
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_008, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_009
 * @tc.name      : HksCryptoHalAesDecrypt_009
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_009, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_009_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_010
 * @tc.name      : HksCryptoHalAesDecrypt_010
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_010, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_010_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_011
 * @tc.name      : HksCryptoHalAesDecrypt_011
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_011, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_012
 * @tc.name      : HksCryptoHalAesDecrypt_012
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-192-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_012, Function | SmallTest | Level0)
{
    GcmRunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_012_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_013
 * @tc.name      : HksCryptoHalAesDecrypt_013
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_013, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_014
 * @tc.name      : HksCryptoHalAesDecrypt_014
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_014, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_015
 * @tc.name      : HksCryptoHalAesDecrypt_015
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_015, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_016
 * @tc.name      : HksCryptoHalAesDecrypt_016
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_016, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_016_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_017
 * @tc.name      : HksCryptoHalAesDecrypt_017
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_017, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesDecrypt_018
 * @tc.name      : HksCryptoHalAesDecrypt_018
 * @tc.desc      : Using HksCryptoHalDecrypt Decrypt AES-256-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesDecrypt, HksCryptoHalAesDecrypt_018, Function | SmallTest | Level0)
{
    GcmRunTestCase(HKS_CRYPTO_HAL_AES_DECRYPT_018_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS