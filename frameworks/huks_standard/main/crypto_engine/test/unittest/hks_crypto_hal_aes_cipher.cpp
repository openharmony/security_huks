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
    HksKeySpec spec;
    HksUsageSpec usageSpec;
    std::string hexData;

    HksErrorCode generateKeyResult;
    HksErrorCode encryptResult;
    HksErrorCode decryptResult;
};

const uint8_t IV[16] = {0};
const HksCipherParam tagIv = { .iv = { .size = 16, .data = (uint8_t *)IV } };
const HksAeadParam aeadParam = {
    .nonce = { .size = 16, .data = (uint8_t *)IV },
    .aad = { .size = 0, .data = nullptr },
    .tagLenEnc = 16,
    .payloadLen = 0,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_004_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_005_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_006_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_128,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&aeadParam,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_007_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_008_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_009_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_010_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_011_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_012_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_192,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&aeadParam,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_013_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_014_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_015_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&tagIv,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_016_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_017_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_CIPHER_018_PARAMS = {
    .spec = {
        .algType = HKS_ALG_AES,
        .keyLen = HKS_AES_KEY_SIZE_256,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&aeadParam,
    },
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalAesCipher : public HksCryptoHalCommon, public testing::Test {
protected:
    void RunTestCase(const TestCaseParams &testCaseParams)
    {
        HksBlob key = { .size = 0, .data = nullptr };

        uint32_t inLen = testCaseParams.hexData.length() / 2;
        uint32_t outLen = (inLen + HKS_PADDING_SUPPLENMENT) / HKS_PADDING_SUPPLENMENT * HKS_PADDING_SUPPLENMENT;

        HksBlob message = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        for (uint32_t ii = 0; ii < inLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[2 * ii]);
        }
        HksBlob cipherText = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };
        HksBlob plaintext = { .size = outLen, .data = (uint8_t *)HksMalloc(outLen) };
        HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };

        EXPECT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);
        EXPECT_EQ(HksCryptoHalEncrypt(&key, &testCaseParams.usageSpec, &message, &cipherText, &tagAead),
            testCaseParams.encryptResult);
        if (testCaseParams.encryptResult != HKS_ERROR_NOT_SUPPORTED) {
            if (testCaseParams.usageSpec.mode == HKS_MODE_GCM) {
                struct HksAeadParam aeadParamForGcm;
                aeadParamForGcm.nonce = { .size = 16, .data = (uint8_t *)IV };
                aeadParamForGcm.aad = { .size = 0, .data = nullptr };
                aeadParamForGcm.tagDec = tagAead;
                aeadParamForGcm.payloadLen = 0;
                HksUsageSpec usageSpecForGCM = {
                    .algType = HKS_ALG_AES,
                    .mode = HKS_MODE_GCM,
                    .padding = HKS_PADDING_NONE,
                    .digest = HKS_DIGEST_NONE,
                    .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
                    .algParam = &aeadParamForGcm,
                };
                EXPECT_EQ(
                    HksCryptoHalDecrypt(&key, &usageSpecForGCM, &cipherText, &plaintext), testCaseParams.decryptResult);
            } else {
                EXPECT_EQ(HksCryptoHalDecrypt(&key, &testCaseParams.usageSpec, &cipherText, &plaintext),
                    testCaseParams.decryptResult);
            }
            EXPECT_EQ(message.size, plaintext.size);
            EXPECT_EQ(HksMemCmp(message.data, plaintext.data, plaintext.size), HKS_SUCCESS);
        }

        HksFree(key.data);
        HksFree(cipherText.data);
        HksFree(plaintext.data);
        HksFree(tagAead.data);
    }
};

/**
 * @tc.number    : HksCryptoHalAesCipher_001
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CBC-NOPADDING key
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_002
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_003
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_003, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_003_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_004
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_004, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_004_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_005
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_005, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_006
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-128-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_006, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_006_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_007
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_007, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_008
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_008, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_009
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_009, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_009_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_010
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_010, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_010_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_011
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_011, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_012
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-192-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_012, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_012_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_013
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_013, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_014
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_014, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_015
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_015, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_016
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_016, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_016_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_017
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_017, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesCipher_018
 * @tc.name      :
 * @tc.desc      : Generate key and Encrypt / Decrypt AES-256-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesCipher, HksCryptoHalAesCipher_018, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_CIPHER_018_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS
