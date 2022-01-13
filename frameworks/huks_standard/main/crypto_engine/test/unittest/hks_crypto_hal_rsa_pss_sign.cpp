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
    HksKeySpec spec;
    HksUsageSpec usageSpec;
    std::string hexData;

    HksErrorCode generateKeyResult;
    HksErrorCode signResult;
    HksErrorCode verifyResult;
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_004_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_005_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_006_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_007_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_008_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_009_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_010_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_011_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_012_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_013_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_014_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_015_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_016_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_017_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_018_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_019_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_MBEDTLS_)
    .signResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_OPENSSL_)
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_020_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_021_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_022_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_023_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_024_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_025_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_MBEDTLS_)
    .signResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_OPENSSL_)
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_026_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_027_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_028_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PSS_SIGN_029_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PSS,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalRsaPssSign : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
protected:
    void RunTestCase(const TestCaseParams &testCaseParams)
    {
        HksBlob key = { .size = 0, .data = nullptr };

        EXPECT_EQ(HksCryptoHalGenerateKey(&testCaseParams.spec, &key), testCaseParams.generateKeyResult);

        uint32_t dataLen = testCaseParams.hexData.length() / 2;

        HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
        for (uint32_t ii = 0; ii < dataLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[2 * ii]);
        }

        uint8_t hashData[HKS_HMAC_DIGEST_SHA512_LEN] = {0};
        struct HksBlob hash = { HKS_HMAC_DIGEST_SHA512_LEN, hashData };
        EXPECT_EQ(HksCryptoHalHash(testCaseParams.usageSpec.digest, &message, &hash), HKS_SUCCESS);

        struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

        EXPECT_EQ(HksCryptoHalSign(&key, &testCaseParams.usageSpec, &hash, &signature), testCaseParams.signResult);

        if (testCaseParams.signResult == HKS_SUCCESS) {
            struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };
            EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

            EXPECT_EQ(HksCryptoHalVerify(&pubKey, &testCaseParams.usageSpec, &hash, &signature),
                testCaseParams.verifyResult);
            HksFree(pubKey.data);
        }
        HksFree(message.data);
        HksFree(signature.data);
        HksFree(key.data);
    }
};

void HksCryptoHalRsaPssSign::SetUpTestCase(void)
{
}

void HksCryptoHalRsaPssSign::TearDownTestCase(void)
{
}

void HksCryptoHalRsaPssSign::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaPssSign::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_001
 * @tc.name      : HksCryptoHalRsaPssSign_001
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_001, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_002
 * @tc.name      : HksCryptoHalRsaPssSign_002
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_002, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_003
 * @tc.name      : HksCryptoHalRsaPssSign_003
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_003, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_003_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_004
 * @tc.name      : HksCryptoHalRsaPssSign_004
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_004, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_004_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPssSign_005
 * @tc.name      : HksCryptoHalRsaPssSign_005
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_005, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_006
 * @tc.name      : HksCryptoHalRsaPssSign_006
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_006, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_006_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPssSign_007
 * @tc.name      : HksCryptoHalRsaPssSign_007
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_007, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_008
 * @tc.name      : HksCryptoHalRsaPssSign_008
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_008, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_009
 * @tc.name      : HksCryptoHalRsaPssSign_009
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_009, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_009_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_010
 * @tc.name      : HksCryptoHalRsaPssSign_010
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_010, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_010_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPssSign_011
 * @tc.name      : HksCryptoHalRsaPssSign_011
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_011, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_012
 * @tc.name      : HksCryptoHalRsaPssSign_012
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_012, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_012_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPssSign_013
 * @tc.name      : HksCryptoHalRsaPssSign_013
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_013, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_014
 * @tc.name      : HksCryptoHalRsaPssSign_014
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_014, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_015
 * @tc.name      : HksCryptoHalRsaPssSign_015
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_015, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_016
 * @tc.name      : HksCryptoHalRsaPssSign_016
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_016, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_016_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPssSign_017
 * @tc.name      : HksCryptoHalRsaPssSign_017
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_017, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_018
 * @tc.name      : HksCryptoHalRsaPssSign_018
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_018, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_018_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPssSign_019
 * @tc.name      : HksCryptoHalRsaPssSign_019
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_019, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_019_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_020
 * @tc.name      : HksCryptoHalRsaPssSign_020
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_020, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_020_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_021
 * @tc.name      : HksCryptoHalRsaPssSign_021
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_021, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_021_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_022
 * @tc.name      : HksCryptoHalRsaPssSign_022
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_022, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_022_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPssSign_023
 * @tc.name      : HksCryptoHalRsaPssSign_023
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_023, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_023_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_024
 * @tc.name      : HksCryptoHalRsaPssSign_024
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_024, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_024_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPssSign_025
 * @tc.name      : HksCryptoHalRsaPssSign_025
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_025, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_025_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_026
 * @tc.name      : HksCryptoHalRsaPssSign_026
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_026, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_026_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_027
 * @tc.name      : HksCryptoHalRsaPssSign_027
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_027, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_027_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPssSign_028
 * @tc.name      : HksCryptoHalRsaPssSign_028
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_028, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_028_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPssSign_029
 * @tc.name      : HksCryptoHalRsaPssSign_029
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PSSPADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPssSign, HksCryptoHalRsaPssSign_029, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PSS_SIGN_029_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS