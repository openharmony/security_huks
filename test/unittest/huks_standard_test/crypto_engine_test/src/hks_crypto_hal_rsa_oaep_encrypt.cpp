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

#include "file_ex.h"
#include "hks_ability.h"
#include "hks_config.h"
#include "hks_crypto_hal.h"
#include "hks_crypto_hal_common.h"
#include "hks_mem.h"
#include "hks_log.h"
#include "hks_params_key_data_01.h"
#include "hks_params_key_data_02.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace UnitTest {
namespace {
struct TestCaseParams {
    HksUsageSpec usageSpec = {0};
    std::string keyData;
    std::string hexData;
    HksKeySize keySize = HksKeySize::HKS_RSA_KEY_SIZE_512;

    HksErrorCode encryptResult = HksErrorCode::HKS_SUCCESS;
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_013_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_013_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccdd",
    .keySize = HKS_RSA_KEY_SIZE_512,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_014_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_014_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_768,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_015_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_015_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_1024,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_016_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_016_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_017_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_017_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_018_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA1,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_018_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_019_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_019_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_512,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_020_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_020_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_768,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_021_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_021_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_1024,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_022_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_022_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_023_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_023_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_024_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA224,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_024_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_025_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_025_PARAMS_KEY_DATA
    .hexData = "00112233",
    .keySize = HKS_RSA_KEY_SIZE_512,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_026_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_026_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccdd",
    .keySize = HKS_RSA_KEY_SIZE_768,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_027_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_027_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_1024,

    .encryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_028_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_028_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_029_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_029_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_030_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA256,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_030_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_031_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_031_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_512,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_032_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_032_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_768,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_033_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_033_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccdd",
    .keySize = HKS_RSA_KEY_SIZE_1024,

    .encryptResult = HKS_SUCCESS,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_034_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_034_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_035_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_035_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_036_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA384,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_036_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_037_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_037_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_512,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_038_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_038_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_768,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_039_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_039_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_1024,
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_040_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_040_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_041_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_041_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,

    .encryptResult = HKS_SUCCESS,
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_042_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_SHA512,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_042_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,

    .encryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_043_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_043_PARAMS_KEY_DATA
    .hexData = "001122334455",
    .keySize = HKS_RSA_KEY_SIZE_512,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_044_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_044_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccdd",
    .keySize = HKS_RSA_KEY_SIZE_768,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_045_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_045_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_1024,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};
#endif

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_046_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_046_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_2048,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_047_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_047_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_3072,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};

const TestCaseParams HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_048_PARAMS = {
    .usageSpec = {
        .algType = HKS_ALG_RSA,
        .mode = HKS_MODE_ECB,
        .padding = HKS_PADDING_OAEP,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
        .algParam = nullptr,
    },
    .keyData = HKS_CRYPTO_HAL_RSA_OAEP_048_PARAMS_KEY_DATA
    .hexData = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    .keySize = HKS_RSA_KEY_SIZE_4096,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_ERROR_CRYPTO_ENGINE_ERROR,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_INVALID_DIGEST,
#endif
};
}  // namespace

class HksCryptoHalRsaOaepEncrypt : public HksCryptoHalCommon, public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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
        uint32_t outLen = HKS_KEY_BYTES(testCaseParams.keySize);

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

void HksCryptoHalRsaOaepEncrypt::SetUpTestCase(void)
{
}

void HksCryptoHalRsaOaepEncrypt::TearDownTestCase(void)
{
}

void HksCryptoHalRsaOaepEncrypt::SetUp()
{
    EXPECT_EQ(HksCryptoAbilityInit(), 0);
}

void HksCryptoHalRsaOaepEncrypt::TearDown()
{
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_013
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_013
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_013, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_013_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_014
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_014
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_014, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_014_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_015
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_015
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_015, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_015_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_016
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_016
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_016, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_016_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_017
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_017
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_017, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_017_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_018
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_018
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP_SHA1 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_018, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_018_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_019
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_019
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_019, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_019_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_020
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_020
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_020, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_020_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_021
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_021
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_021, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_021_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_022
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_022
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_022, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_022_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_023
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_023
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_023, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_023_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_024
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_024
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP_SHA224 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_024, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_024_PARAMS);
}
#endif //CUT_RSA_4096_TEST

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_025
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_025
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP_SHA256 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_025, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_025_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_026
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_026
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_026, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_026_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_027
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_027
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_027, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_027_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_028
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_028
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_028, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_028_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_029
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_029
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_029, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_029_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_030
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_030
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP_SHA256 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_030, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_030_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_031
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_031
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP_SHA384 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_031, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_031_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_032
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_032
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP_SHA384 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_032, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_032_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_033
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_033
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_033, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_033_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_034
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_034
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_034, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_034_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_035
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_035
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_035, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_035_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_036
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_036
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP_SHA384 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_036, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_036_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_037
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_037
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_037, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_037_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_038
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_038
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_038, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_038_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_039
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_039
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP_SHA512 key failed:keysize<sha*2+2.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_039, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_039_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_040
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_040
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_040, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_040_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_041
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_041
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_041, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_041_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_042
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_042
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP_SHA512 key.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_042, Function | SmallTest | Level1)
{
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_042_PARAMS);
}
#endif

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_043
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_043
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-512-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_043, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_043");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_043_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_044
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_044
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-768-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_044, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_044");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_044_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_045
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_045
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-1024-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_045, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_045");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_045_PARAMS);
}
#endif

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_046
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_046
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-2048-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_046, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_046");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_046_PARAMS);
}

#ifndef CUT_RSA_4096_TEST
/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_047
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_047
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-3072-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_047, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_047");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_047_PARAMS);
}

/**
 * @tc.number    : HksCryptoHalRsaOaepEncrypt_048
 * @tc.name      : HksCryptoHalRsaOaepEncrypt_048
 * @tc.desc      : Using HksCryptoHalEncrypt Encrypt RSA-4096-OAEP key failed: wrong digest.
 */
HWTEST_F(HksCryptoHalRsaOaepEncrypt, HksCryptoHalRsaOaepEncrypt_048, Function | SmallTest | Level1)
{
    HKS_LOG_E("Enter HksCryptoHalRsaOaepEncrypt_048");
    RunTestCase(HKS_CRYPTO_HAL_RSA_OAEP_ENCRYPT_048_PARAMS);
}
#endif
}  // namespace UnitTest
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS