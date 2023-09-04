/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_CIPHER_C_H
#define HKS_TEST_CIPHER_C_H

#include "hks_test_cipher.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

#define DEFAULT_AES_CIPHER_PLAIN_SIZE 1000
#define AES_DEFAULT_GCM_NONCE_LENGTH 12
#define AES_DEFAULT_AAD_LEN 4
#define DEFAULT_AES_LOCAL_PARAM_SET_OUT_SIZE 256
#define AES_LOCAL_KEY_SIZE_128 16
#define AES_LOCAL_KEY_SIZE_256 32

static const struct HksTestCipherParams g_testCipherParams[] = {
    /* success: local aes256-gcm-none */
    { 0, HKS_SUCCESS, { false, 0, false, 0 },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            true, HKS_STORAGE_TEMP
        },
        { false, 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            true, false
        },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            true, false
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, AES_LOCAL_KEY_SIZE_256, true, AES_LOCAL_KEY_SIZE_256 }
    },
    { 1, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0
        },
        { false, 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN
        },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { false, 0, false, 0 }
    },
};

static const struct HksTestEncryptParams g_testEncryptParams[] = {
    { 0, HKS_ERROR_CHECK_GET_NONCE_FAIL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            false, 0,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { false, 0, false, 0 }
    },
    { 1, HKS_ERROR_INVALID_NONCE, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH - 1,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { false, 0, false, 0 }
    },
    { 2, HKS_ERROR_CHECK_GET_AAD_FAIL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            false, 0,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { false, 0, false, 0 }
    },
    { 3, HKS_ERROR_INVALID_ARGUMENT, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, 0, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 },
        { false, 0, false, 0 }
    },
    { 4, HKS_ERROR_BUFFER_TOO_SMALL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* encrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_ENCRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 - 1, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 - 1 },
        { false, 0, false, 0 }
    },
};

static const struct HksTestDecryptParams g_testDecryptParams[] = {
    { 0, HKS_ERROR_CHECK_GET_NONCE_FAIL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            false, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 },
        { false, 0, false, 0 }
    },
    { 1, HKS_ERROR_INVALID_NONCE, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH - 1,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 },
        { false, 0, false, 0 }
    },
    { 2, HKS_ERROR_CHECK_GET_AAD_FAIL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            false, 0,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 },
        { false, 0, false, 0 }
    },
    { 3, HKS_ERROR_INVALID_ARGUMENT, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, 16, true, 16 },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 },
        { false, 0, false, 0 }
    },
    { 4, HKS_ERROR_BUFFER_TOO_SMALL, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE },
        {
            true, /* genKey params */
            true, HKS_ALG_AES,
            true, HKS_AES_KEY_SIZE_256,
            true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM
        },
        { 0 },
        {
            HKS_TEST_CIPHER_TYPE_AES, true, /* decrypt params */
            true, HKS_ALG_AES,
            true, HKS_KEY_PURPOSE_DECRYPT,
            false, 0,
            true, HKS_PADDING_NONE,
            true, HKS_MODE_GCM,
            false, 0,
            true, AES_DEFAULT_GCM_NONCE_LENGTH,
            true, AES_DEFAULT_AAD_LEN,
            false, true
        },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE },
        { true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 - 1, true, DEFAULT_AES_CIPHER_PLAIN_SIZE - 16 -1 },
        { false, 0, false, 0 }
    },
};
int32_t ConstructDataToBlobTest(struct HksBlob **inData, struct HksBlob **outData,
    const struct HksTestBlobParams *inTextParams, const struct HksTestBlobParams *outTextParams);

int32_t EncryptTest(struct CipherEncryptStructure *encryptStruct);

int32_t DecryptCipherTest(struct CipherDecryptStructure *decryptStruct);

int32_t Decrypt(struct OnlyDecryptStructure *onlyDecryptStruct);

int32_t BaseTestCipher(uint32_t times, uint32_t index, uint32_t performTimes);

int32_t BaseTestEncrypt(uint32_t times, uint32_t index, uint32_t performTimes);

int32_t BaseTestDecrypt(uint32_t times, uint32_t index, uint32_t performTimes);

#endif