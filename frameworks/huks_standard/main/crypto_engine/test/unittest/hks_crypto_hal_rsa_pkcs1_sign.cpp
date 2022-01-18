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
    HksKeySpec spec = {0};
    HksUsageSpec usageSpec = {0};
    std::string hexData;

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode signResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode verifyResult = HksErrorCode::HKS_SUCCESS;
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_001_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_002_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_003_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_004_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_005_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_006_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_MD5,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_007_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_008_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_009_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_010_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_011_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_012_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_013_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_014_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_015_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_016_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_017_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_018_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_019_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_020_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_021_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_022_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_023_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_024_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_025_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_512,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_026_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_027_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_028_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_029_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_030_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_031_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_032_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_033_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_034_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_035_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_036_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_768,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_037_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_1024,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_038_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_2048,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_039_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_3072,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_040_PARAMS = {
    .spec = {
        .algType = HKS_ALG_RSA,
        .keyLen = HKS_RSA_KEY_SIZE_4096,
        .algParam = nullptr,
    },
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_PKCS1_V1_5,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
    },
    .hexData = "00112233445566778899aabbccddeeff",

    .generateKeyResult = HKS_SUCCESS,
    .signResult = HKS_SUCCESS,
    .verifyResult = HKS_SUCCESS,
};
}  // namespace

class HksCryptoHalRsaPkcs1Sign : public HksCryptoHalCommon, public testing::Test {
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

        uint32_t dataLen = testCaseParams.hexData.length() / HKS_COUNT_OF_HALF;

        HksBlob message = { .size = dataLen, .data = (uint8_t *)HksMalloc(dataLen) };
        for (uint32_t ii = 0; ii < dataLen; ii++) {
            message.data[ii] = ReadHex((const uint8_t *)&testCaseParams.hexData[2 * ii]);
        }

        uint8_t hashData[HKS_HMAC_DIGEST_SHA512_LEN] = {0};
        struct HksBlob hash = { HKS_HMAC_DIGEST_SHA512_LEN, hashData };
        /* NONEwithECDSA default sha256: ec_pkey_ctrl default md nid */
        struct HksUsageSpec usageSpec = testCaseParams.usageSpec;
        uint32_t inputDigest = usageSpec.digest;
        usageSpec.digest = (inputDigest == HKS_DIGEST_NONE) ? HKS_DIGEST_SHA256 : inputDigest;
        EXPECT_EQ(HksCryptoHalHash(usageSpec.digest, &message, &hash), HKS_SUCCESS);

        struct HksBlob signature = { .size = 512, .data = (uint8_t *)HksMalloc(512) };

        EXPECT_EQ(HksCryptoHalSign(&key, &usageSpec, &hash, &signature), testCaseParams.signResult);

        struct HksBlob pubKey = { .size = 1044, .data = (uint8_t *)HksMalloc(1044) };

        EXPECT_EQ(HksCryptoHalGetPubKey(&key, &pubKey), HKS_SUCCESS);

        EXPECT_EQ(
            HksCryptoHalVerify(&pubKey, &usageSpec, &hash, &signature), testCaseParams.verifyResult);

        HksFree(message.data);
        HksFree(signature.data);
        HksFree(pubKey.data);
        HksFree(key.data);
    }
};

void HksCryptoHalRsaPkcs1Sign::SetUpTestCase(void)
{
}

void HksCryptoHalRsaPkcs1Sign::TearDownTestCase(void)
{
}

void HksCryptoHalRsaPkcs1Sign::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaPkcs1Sign::TearDown()
{
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_001
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_001
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_001, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_001_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_002
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_002
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_002, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_002_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_003
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_003
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_003, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_003_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_004
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_004
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_004, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_004_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_005
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_005
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_005, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_005_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_006
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_006
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-MD5 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_006, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_006_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_007
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_007
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_007, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_007_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_008
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_008
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_008, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_008_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_009
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_009
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_009, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_009_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_010
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_010
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_010, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_010_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_011
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_011
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_011, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_011_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_012
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_012
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-NONE key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_012, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_012_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_013
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_013
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_013, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_014
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_014
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_014, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_015
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_015
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_015, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_016
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_016
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_016, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_016_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_017
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_017
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_017, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_018
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_018
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_018, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_018_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_019
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_019
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_019, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_019_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_020
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_020
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_020, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_020_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_021
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_021
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_021, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_021_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_022
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_022
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_022, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_022_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_023
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_023
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_023, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_023_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_024
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_024
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_024, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_024_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_025
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_025
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-512-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_025, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_025_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_026
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_026
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_026, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_026_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_027
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_027
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_027, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_027_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_028
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_028
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_028, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_028_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_029
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_029
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_029, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_029_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_030
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_030
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_030, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_030_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_031
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_031
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_031, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_031_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_032
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_032
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_032, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_032_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_033
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_033
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_033, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_033_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_034
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_034
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_034, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_034_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_035
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_035
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_035, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_035_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_036
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_036
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-768-PKCS1PADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_036, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_036_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_037
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_037
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-1024-PKCS1PADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_037, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_037_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_038
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_038
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-2048-PKCS1PADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_038, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_038_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_039
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_039
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-3072-PKCS1PADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_039, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_039_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaPkcs1Sign_040
 * @tc.name      : HksCryptoHalRsaPkcs1Sign_040
 * @tc.desc      : Using HksCryptoHalSign Sign RSA-4096-PKCS1PADDING-SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaPkcs1Sign, HksCryptoHalRsaPkcs1Sign_040, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_PKCS1_SIGN_040_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS