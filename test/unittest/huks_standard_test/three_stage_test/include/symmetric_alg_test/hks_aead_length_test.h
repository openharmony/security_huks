/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_AEAD_LENGTH_TEST_H
#define HKS_AEAD_LENGTH_TEST_H

#include "hks_type.h"
#include <vector>
#include <cstring>

#ifdef L2_STANDARD
namespace Unittest::HksAeadLengthPartTest {

#define MAX_KEY_BLOB_SIZE 1024
#define MAX_TEST_BLOB_SIZE 1024
#define AAD_SIZE 16
#define INVALID_AEAD_TAG_LEN 21

/*
 * std::tuple<[encrypt aead tag len], [encrypt expected], [decrypt aead tag len], [decrypt expected]>
 */
using AeadLenAndExpect = std::tuple<uint32_t, int32_t, uint32_t, int32_t>;

const std::vector<AeadLenAndExpect> aesGcmEncAndDecExpected = {
    {INVALID_AEAD_TAG_LEN, HKS_SUCCESS, INVALID_AEAD_TAG_LEN, HKS_SUCCESS}, // not indicate aead tag length
    {16, HKS_SUCCESS, 16, HKS_SUCCESS}
};

const std::vector<AeadLenAndExpect> aesGcmEncAndDecExpected1 = {
    {16, HKS_SUCCESS, 12, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID}
};

const std::vector<std::pair<uint32_t, int32_t>> aesGcmEncExpected = {
    {12, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {20, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID}
};

const std::vector<AeadLenAndExpect> aesCcmEncAndDecExpected = {
    {INVALID_AEAD_TAG_LEN, HKS_SUCCESS, INVALID_AEAD_TAG_LEN, HKS_SUCCESS},
    {4, HKS_SUCCESS, 4, HKS_SUCCESS},
    {6, HKS_SUCCESS, 6, HKS_SUCCESS},
    {8, HKS_SUCCESS, 8, HKS_SUCCESS},
    {10, HKS_SUCCESS, 10, HKS_SUCCESS},
    {12, HKS_SUCCESS, 12, HKS_SUCCESS},
    {14, HKS_SUCCESS, 14, HKS_SUCCESS},
    {16, HKS_SUCCESS, 16, HKS_SUCCESS}
};

const std::vector<std::pair<uint32_t, int32_t>> aesCcmEncExpected = {
    {0, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {1, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {2, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {3, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {5, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {7, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {9, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {11, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {13, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {15, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {17, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID},
    {18, HKS_ERROR_CODE_AEAD_TAG_LEN_INVALID}
};

char g_aeadTag[HKS_AE_TAG_LEN + 1] = { 0 };
char g_cipherText[MAX_TEST_BLOB_SIZE] = {0};
const char g_nonce[HKS_AE_NONCE_LEN + 1] = { 0 };
const char g_keyAlias[] = "AesTestKeyAlias";
const char g_plainText[] = "This is a test for indicate aes-gcm/ccm aead length";
const uint8_t AAD_DATA[AAD_SIZE] = {0};

struct HksBlob g_localKey = {
    .size = 0,
    .data = nullptr
};

const struct HksBlob g_keyBlob = {
    .size = static_cast<uint32_t>(strlen(g_keyAlias)),
    .data = (uint8_t *)g_keyAlias
};

struct HksBlob g_plainBlob = {
    .size = static_cast<uint32_t>(strlen(g_plainText)),
    .data = (uint8_t *)g_plainText
};

struct HksBlob g_cipherBlob = {
    .size = MAX_TEST_BLOB_SIZE,
    .data = (uint8_t *)g_cipherText
};

/* if need indicate aead tag length, add this param */
struct HksParam g_aeadLenParam = {
    .tag = HKS_TAG_AE_TAG_LEN,
    .uint32Param = HKS_AE_TAG_LEN
};

/* if three stage decrypt, add this param */
struct HksParam g_aeadTagParam = {
    .tag = HKS_TAG_AE_TAG,
    .blob = {
        .size = HKS_AE_TAG_LEN,
        .data = (uint8_t *)g_aeadTag
    }
};

/* if test local, add this param to generate key */
struct HksParam g_localParam = {
    .tag = HKS_TAG_KEY_STORAGE_FLAG,
    .uint32Param = HKS_STORAGE_TEMP
};

/* if test local, add this param to encrypt or decrypt */
struct HksParam g_isAliasParam = {
    .tag = HKS_TAG_IS_KEY_ALIAS,
    .boolParam = false
};

/* param for generating key */
struct HksParam g_genAesKey[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    },
    {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    },
    {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }
};

/* param for AES-GCM encrypt and decrypt */
struct HksParam g_aesGcmEncrypt[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    },
    {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    },
    {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    },
    {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
    {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    },
    {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = HKS_AE_NONCE_LEN,
            .data = (uint8_t *)(g_nonce)
        }
    }
};

struct HksParam g_aesGcmDecrypt[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    },
    {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    },
    {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    },
    {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
    {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_GCM
    },
    {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = HKS_AE_NONCE_LEN,
            .data = (uint8_t *)(g_nonce)
        }
    }
};

/* param for AES-CCM encrypt and decrypt */
struct HksParam g_aesCcmEncrypt[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    },
    {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    },
    {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    },
    {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
    {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    },
    {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = HKS_AE_NONCE_LEN,
            .data = (uint8_t *)(g_nonce)
        }
    },
    {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = sizeof(AAD_DATA),
            .data = (uint8_t*)AAD_DATA
        }
    }
};

struct HksParam g_aesCcmDecrypt[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    },
    {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_256
    },
    {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    },
    {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    },
    {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CCM
    },
    {
        .tag = HKS_TAG_NONCE,
        .blob = {
            .size = HKS_AE_NONCE_LEN,
            .data = (uint8_t *)(g_nonce)
        }
    },
    {
        .tag = HKS_TAG_ASSOCIATED_DATA,
        .blob = {
            .size = sizeof(AAD_DATA),
            .data = (uint8_t*)AAD_DATA
        }
    }
};

}

#endif // L2_STANDARD
#endif // HKS_AEAD_LENGTH_TEST_H