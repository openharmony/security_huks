/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "openssl_aes_helper.h"

#ifdef L2_STANDARD
#include "file_ex.h"
#endif

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace Huks {
namespace MT {
namespace {
struct TestCaseParams {
    std::vector<HksParam> params;
    std::string hexData;
    uint32_t inLenAppend = 0;

    HksErrorCode generateKeyResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode encryptResult = HksErrorCode::HKS_SUCCESS;
    HksErrorCode decryptResult = HksErrorCode::HKS_SUCCESS;
};

const uint8_t IV[IV_SIZE] = {0};
const uint8_t AAD_DATA[AAD_SIZE] = {0};
const char TEST_AES_KEY[] = "This is a AES key";

const TestCaseParams HUKS_AES_CIPER_MT_00100_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = COMPLEMENT_LEN,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00200_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00300_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HUKS_AES_CIPER_MT_00400_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00500_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HUKS_AES_CIPER_MT_00600_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(AAD_DATA), .data = (uint8_t*)AAD_DATA } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00700_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = COMPLEMENT_LEN,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00800_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_00900_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HUKS_AES_CIPER_MT_01000_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_01100_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HUKS_AES_CIPER_MT_01200_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_192 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(AAD_DATA), .data = (uint8_t*)AAD_DATA } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_01300_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = COMPLEMENT_LEN,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_01400_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_01500_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CTR },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

#ifdef HKS_UNTRUSTED_RUNNING_ENV
const TestCaseParams HUKS_AES_CIPER_MT_01600_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};

const TestCaseParams HUKS_AES_CIPER_MT_01700_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        { .tag = HKS_TAG_IV, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
#if defined(_USE_OPENSSL_)
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
#endif
#if defined(_USE_MBEDTLS_)
    .encryptResult = HKS_ERROR_NOT_SUPPORTED,
#endif
};
#endif

const TestCaseParams HUKS_AES_CIPER_MT_01800_PARAMS = {
    .params = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_NONCE, .blob = { .size = IV_SIZE, .data = (uint8_t*)IV } },
        { .tag = HKS_TAG_ASSOCIATED_DATA, .blob = { .size = sizeof(AAD_DATA), .data = (uint8_t*)AAD_DATA } },
    },
    .hexData = "0123456789abcdef",
    .inLenAppend = 0,
    .generateKeyResult = HKS_SUCCESS,
    .encryptResult = HKS_SUCCESS,
    .decryptResult = HKS_SUCCESS,
};
}  // namespace

class HksAesCipherMt : public testing::Test {
protected:
    void RunTestCase(const TestCaseParams &testCaseParams)
    {
        struct HksBlob authId = { (uint32_t)strlen(TEST_AES_KEY), (uint8_t *)TEST_AES_KEY };

        struct HksParamSet *paramInSet = nullptr;
        HksInitParamSet(&paramInSet);

        HksAddParams(paramInSet, testCaseParams.params.data(), testCaseParams.params.size());
        HksBuildParamSet(&paramInSet);

        EXPECT_EQ(HksGenerateKey(&authId, paramInSet, nullptr), testCaseParams.generateKeyResult);

        HksBlob plainText = {
            .size = (uint32_t)testCaseParams.hexData.length(),
            .data = (uint8_t *)&testCaseParams.hexData[0],
        };

        uint32_t inLen = testCaseParams.hexData.length() + COMPLEMENT_LEN;
        HksBlob cipherText = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
        ASSERT_NE(cipherText.data, nullptr);
        EXPECT_EQ(HksEncrypt(&authId, paramInSet, &plainText, &cipherText), testCaseParams.encryptResult);
        if (testCaseParams.encryptResult != HKS_ERROR_NOT_SUPPORTED) {
            HksBlob plainTextDecrypt = { .size = inLen, .data = (uint8_t *)HksMalloc(inLen) };
            ASSERT_NE(plainTextDecrypt.data, nullptr);
            EXPECT_EQ(HksDecrypt(&authId, paramInSet, &cipherText, &plainTextDecrypt), testCaseParams.decryptResult);
            EXPECT_EQ(plainTextDecrypt.size, testCaseParams.hexData.length());
            EXPECT_EQ(HksMemCmp(plainText.data, plainTextDecrypt.data, testCaseParams.hexData.length()), 0);
            HKS_FREE(plainTextDecrypt.data);
        }

        (void)HksDeleteKey(&authId, nullptr);
        HKS_FREE(cipherText.data);
        HksFreeParamSet(&paramInSet);
    }

public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);
};

void HksAesCipherMt::SetUpTestCase(void)
{
}

void HksAesCipherMt::TearDownTestCase(void)
{
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00100
 * @tc.name      : HksAesCipherMt00100
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00100, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00100_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00200
 * @tc.name      : HksAesCipherMt00200
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00200, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00200_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00300
 * @tc.name      : HksAesCipherMt00300
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00300, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00300_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00400
 * @tc.name      : HksAesCipherMt00400
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00400, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00400_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00500
 * @tc.name      : HksAesCipherMt00500
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00500, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00500_PARAMS);
}
#endif

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00600
 * @tc.name      : HksAesCipherMt00600
 * @tc.desc      : Huks generates an aes128 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00600, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00600_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00700
 * @tc.name      : HksAesCipherMt00700
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00700, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00700_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00800
 * @tc.name      : HksAesCipherMt00800
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00800, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00800_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt00900
 * @tc.name      : HksAesCipherMt00900
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt00900, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_00900_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01000
 * @tc.name      : HksAesCipherMt01000
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01000, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01000_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01100
 * @tc.name      : HksAesCipherMt01100
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01100, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01100_PARAMS);
}
#endif

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01200
 * @tc.name      : HksAesCipherMt01200
 * @tc.desc      : Huks generates an aes192 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01200, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01200_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01300
 * @tc.name      : HksAesCipherMt01300
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01300, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01300_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01400
 * @tc.name      : HksAesCipherMt01400
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CBC/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01400, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01400_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01500
 * @tc.name      : HksAesCipherMt01500
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/CTR/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01500, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01500_PARAMS);
}

#ifdef HKS_UNTRUSTED_RUNNING_ENV
/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01600
 * @tc.name      : HksAesCipherMt01600
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01600, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01600_PARAMS);
}

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01700
 * @tc.name      : HksAesCipherMt01700
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/ECB/pkcs7padding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01700, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01700_PARAMS);
}
#endif

/**
 * @tc.number    : HksAesCipherMt.HksAesCipherMt01800
 * @tc.name      : HksAesCipherMt01800
 * @tc.desc      : Huks generates an aes256 bit key, which can be successfully used by huks to encrypt/decrypt using
 * AES/GCM/nopadding algorithm
 */
HWTEST_F(HksAesCipherMt, HksAesCipherMt01800, TestSize.Level0)
{
    RunTestCase(HUKS_AES_CIPER_MT_01800_PARAMS);
}
}  // namespace MT
}  // namespace Huks
}  // namespace Security
}  // namespace OHOS