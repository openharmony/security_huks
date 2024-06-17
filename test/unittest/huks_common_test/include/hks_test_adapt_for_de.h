/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HKS_TEST_ADAPT_FOR_DE_H
#define HKS_TEST_ADAPT_FOR_DE_H

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ConstructNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **newParamSet);

int32_t HksGenerateKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut);

int32_t HksImportKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key);

int32_t HksImportWrappedKeyForDe(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);

int32_t HksExportPublicKeyForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key);

int32_t HksDeleteKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

int32_t HksGetKeyParamSetForDe(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut);

int32_t HksKeyExistForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

int32_t HksSignForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature);

int32_t HksVerifyForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature);

int32_t HksEncryptForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText);

int32_t HksDecryptForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText);

int32_t HksAgreeKeyForDe(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

int32_t HksDeriveKeyForDe(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey);

int32_t HksMacForDe(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac);

int32_t HksGetKeyInfoListForDe(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount);

int32_t HksAttestKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain);

int32_t HksAnonAttestKeyForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain);

int32_t HksInitForDe(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token);

int32_t HksUpdateForDe(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

int32_t HksFinishForDe(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

#ifdef __cplusplus
}
#endif
#endif