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

#include <gtest/gtest.h>
#include <iostream>

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
    HksUsageSpec usageSpec;
    std::string keyData;
    std::string hexData;

    HksErrorCode encryptResult;
};

uint8_t IV[16] = {0};
HksCipherParam tagIv = { .iv = { .size = 16, .data = IV } };
HksAeadParam aeadParam = {
    .nonce = { .size = 16, .data = IV },
    .aad = { .size = 0, .data = nullptr },
    .tagLenEnc = 16,
    .payloadLen = 0,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_001_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_002_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_003_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_004_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_005_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff",
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_006_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    },
    .keyData = "933c213c1f8c844ffcc03f5f7e146a88",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_007_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_008_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_009_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_010_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_011_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff",
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_012_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    },
    .keyData = "7be3cb2c4c900fb318e9c89f828baf9b91783f47c6e8d088",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_013_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_014_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CBC,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_015_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_CTR,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &tagIv,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_016_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_017_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS7,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_AES_ENCRYPT_018_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = &aeadParam,
    },
    .keyData = "57095bd2ba60c34eaafaa77d694eb809af366810fba500ea660a5048b14b212f",
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",

    .encryptResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalAesEncrypt : public HksCryptoHalCommon, public testing::Test {
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
        HksBlob tagAead = { .size = 16, .data = (uint8_t *)HksMalloc(16) };
        EXPECT_EQ(HksCryptoHalEncrypt(&key, &testCaseParams.usageSpec, &message, &cipherText, &tagAead),
            testCaseParams.encryptResult);
        HksFree(key.data);
        HksFree(message.data);
        HksFree(cipherText.data);
        HksFree(tagAead.data);
    }
};

/**
 * @tc.number    : HksCryptoHalAesEncrypt_001
 * @tc.name      : HksCryptoHalAesEncrypt_001
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_001, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_002
 * @tc.name      : HksCryptoHalAesEncrypt_002
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_002, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_003
 * @tc.name      : HksCryptoHalAesEncrypt_003
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_003, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_003_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_004
 * @tc.name      : HksCryptoHalAesEncrypt_004
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_004, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_004_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_005
 * @tc.name      : HksCryptoHalAesEncrypt_005
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_005, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_006
 * @tc.name      : HksCryptoHalAesEncrypt_006
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-128-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_006, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_006_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_007
 * @tc.name      : HksCryptoHalAesEncrypt_007
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_007, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_008
 * @tc.name      : HksCryptoHalAesEncrypt_008
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_008, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_009
 * @tc.name      : HksCryptoHalAesEncrypt_009
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_009, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_009_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_010
 * @tc.name      : HksCryptoHalAesEncrypt_010
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_010, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_010_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_011
 * @tc.name      : HksCryptoHalAesEncrypt_011
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_011, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_012
 * @tc.name      : HksCryptoHalAesEncrypt_012
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-192-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_012, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_012_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_013
 * @tc.name      : HksCryptoHalAesEncrypt_013
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CBC-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_013, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_014
 * @tc.name      : HksCryptoHalAesEncrypt_014
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CBC-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_014, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_015
 * @tc.name      : HksCryptoHalAesEncrypt_015
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-CTR-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_015, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_016
 * @tc.name      : HksCryptoHalAesEncrypt_016
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-ECB-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_016, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_016_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_017
 * @tc.name      : HksCryptoHalAesEncrypt_017
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-ECB-PKCS7PADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_017, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalAesEncrypt_018
 * @tc.name      : HksCryptoHalAesEncrypt_018
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt AES-256-GCM-NOPADDING key.
 */
HWTEST_F(HksCryptoHalAesEncrypt, HksCryptoHalAesEncrypt_018, Function | SmallTest | Level0)
{
    RunTestCase(HKS_CRYPTO_HAL_AES_ENCRYPT_018_PARAMS);
}
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS