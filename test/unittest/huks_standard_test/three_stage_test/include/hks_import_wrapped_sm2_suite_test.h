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

#ifndef HKS_IMPORT_WRAPPED_SM2_SUITE_TEST_H
#define HKS_IMPORT_WRAPPED_SM2_SUITE_TEST_H

#include "hks_api.h"
#include "hks_type.h"

#define NUMBER_9_IN_DECIMAL 9
#define BYTE_TO_HEX_OPER_LENGTH 2
namespace Unittest::ImportWrappedKey {
    static const uint32_t HKS_SM4_IV_SIZE = 16;
    static const uint32_t SM2_COMMON_SIZE = 1024;
    static const uint32_t HKS_SM4_DERIVE_KEY_SIZE = 16;
    static const uint32_t HKS_SM4_CIPHER_SIZE = 128;
    static const uint32_t HKS_COMMON_MAC_SIZE = 256;
    static const uint32_t TAG_ALG_PURPOSE_TYPE_ID = 1;
    static const uint32_t TAG_ALG_IMPORT_KEY_TYPE_ID = 3;
    static const uint32_t TAG_ALG_SUIT_ID = 5;
    static const uint32_t HKS_IMPORT_WRAPPED_KEY_NO_VERIFY_TOTAL_BLOBS = 8;

    struct HksSmTestParams {
        struct HksBlob *wrappingKeyAlias;
        struct HksParamSet *genWrappingKeyParam;

        struct HksBlob *callerKeyAlias;
        struct HksParamSet *genCallerKeyParam;

        struct HksParamSet *signParam;

        struct HksParamSet *deriveKey1Param;
        struct HksParamSet *deriveKey2Param;

        struct HksBlob *importderiveKey1Alias;
        struct HksParamSet *importderiveKey1Param;
        struct HksBlob *importderiveKey2Alias;
        struct HksParamSet *importderiveKey2Param;

        struct HksBlob *importKekAlias;
        struct HksParamSet *importKekParam;

        struct HksParamSet *hmacParam;

        struct HksParamSet *sm2EncryptParam;
        struct HksParamSet *sm4EncryptParam;

        struct HksBlob *importKeyAlias;
        struct HksParamSet *importKeyParam;
        uint32_t keyMaterialLen;
        struct HksBlob *keyImportPlainText;
    };
    void HksImportWrappedKeyTestSm2Suite001(void);
    void HksImportWrappedKeyTestSm2Suite002(void);
    void HksImportWrappedKeyTestSm2Suite003(void);
    void HksImportWrappedKeyTestSm2Suite004(void);
    void HksImportWrappedKeyTestSm2Suite005(void);
    void HksImportWrappedKeyTestSm2Suite006(void);
    void HksImportWrappedKeyTestSm2Suite007(void);
    void HksImportWrappedKeyTestSm2Suite008(void);
}

#endif // HKS_IMPORT_WRAPPED_SM2_SUITE_TEST_H
