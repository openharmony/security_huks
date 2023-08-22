/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "hks_modify_key_test.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_cipher.h"
#include "hks_test_common.h"
#include "hks_test_file_operator.h"
#include "hks_test_log.h"
#include "hks_test_mem.h"

#define G_TEST_CIPHER_PARAMS \
{ 0, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE }, \
    { \
        true, /* genKey params */ \
        true, HKS_ALG_AES, \
        true, HKS_AES_KEY_SIZE_256, \
        true, HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT, \
        false, 0, \
        true, HKS_PADDING_NONE, \
        true, HKS_MODE_GCM, \
        false, 0 \
    }, \
    { false, 0 }, \
    { \
        HKS_TEST_CIPHER_TYPE_AES,  true, /* encrypt params */ \
        true, HKS_ALG_AES, \
        true, HKS_KEY_PURPOSE_ENCRYPT, \
        false, 0, \
        true, HKS_PADDING_NONE, \
        true, HKS_MODE_GCM, \
        false, 0, \
        true, AES_DEFAULT_GCM_NONCE_LENGTH, \
        true, AES_DEFAULT_AAD_LEN \
    }, \
    { \
        HKS_TEST_CIPHER_TYPE_AES,  true, /* decrypt params */ \
        true, HKS_ALG_AES, \
        true, HKS_KEY_PURPOSE_DECRYPT, \
        false, 0, \
        true, HKS_PADDING_NONE, \
        true, HKS_MODE_GCM, \
        false, 0, \
        true, AES_DEFAULT_GCM_NONCE_LENGTH, \
        true, AES_DEFAULT_AAD_LEN \
    }, \
    { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE }, \
    { true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16, true, DEFAULT_AES_CIPHER_PLAIN_SIZE + 16 }, \
    { true, DEFAULT_AES_CIPHER_PLAIN_SIZE, true, DEFAULT_AES_CIPHER_PLAIN_SIZE }, \
    { false, 0, false, 0 } \
},

#ifdef __cplusplus
extern "C" {
#endif
int32_t ConstructDataToBlob(struct HksBlob **inData, struct HksBlob **outData,
    const struct HksTestBlobParams *inTextParams, const struct HksTestBlobParams *outTextParams);

int32_t Encrypt(struct CipherEncryptStructure *encryptStruct);

int32_t DecryptCipher(struct CipherDecryptStructure *decryptStruct);

int32_t GenerateKeyTwo(struct HksBlob *keyAlias, const struct HksTestBlobParams *keyAliasParams,
    const struct HksTestGenKeyParamsParamSet *genKeyParamSetParams,
    const struct HksTestGenKeyParamsParamSetOut *genKeyParamSetParamsOut);
#ifdef __cplusplus
}
#endif