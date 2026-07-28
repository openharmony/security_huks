/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HUKS_HDI_WRAPPER_H
#define HUKS_HDI_WRAPPER_H

#include "v1_2/ihuks_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct HuksBlob;
struct HuksParamSet;
struct HuksEncapsulationResult;
enum HuksChipsetPlatformDecryptScene;

typedef enum {
    HUKS_HDI_VERSION_INVALID = 0,
    HUKS_HDI_VERSION_V1_1 = 1,
    HUKS_HDI_VERSION_V1_2 = 2,
} HuksHdiVersion;

typedef struct HuksHdiWrapper {
    void *hdiInstance;
    HuksHdiVersion version;
    
    int32_t (*ModuleInit)(void);
    int32_t (*ModuleDestroy)(void);
    int32_t (*GenerateKey)(const struct HuksBlob *keyAlias, const struct HuksParamSet *paramSet,
        const struct HuksBlob *keyIn, struct HuksBlob *keyOut);
    int32_t (*ImportKey)(const struct HuksBlob *keyAlias, const struct HuksBlob *key,
        const struct HuksParamSet *paramSet, struct HuksBlob *keyOut);
    int32_t (*ImportWrappedKey)(const struct HuksBlob *wrappingKeyAlias, const struct HuksBlob *key,
        const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet,
        struct HuksBlob *keyOut);
    int32_t (*ExportPublicKey)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        struct HuksBlob *keyOut);
    int32_t (*Init)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        struct HuksBlob *handle, struct HuksBlob *token);
    int32_t (*Update)(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
        const struct HuksBlob *inData, struct HuksBlob *outData);
    int32_t (*Finish)(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
        const struct HuksBlob *inData, struct HuksBlob *outData);
    int32_t (*Abort)(const struct HuksBlob *handle, const struct HuksParamSet *paramSet);
    int32_t (*CheckKeyValidity)(const struct HuksParamSet *paramSet, const struct HuksBlob *key);
    int32_t (*AttestKey)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        struct HuksBlob *certChain);
    int32_t (*GenerateRandom)(const struct HuksParamSet *paramSet, struct HuksBlob *random);
    int32_t (*Sign)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        const struct HuksBlob *srcData, struct HuksBlob *signature);
    int32_t (*Verify)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        const struct HuksBlob *srcData, const struct HuksBlob *signature);
    int32_t (*Encrypt)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        const struct HuksBlob *plainText, struct HuksBlob *cipherText);
    int32_t (*Decrypt)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        const struct HuksBlob *cipherText, struct HuksBlob *plainText);
    int32_t (*AgreeKey)(const struct HuksParamSet *paramSet, const struct HuksBlob *privateKey,
        const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey);
    int32_t (*DeriveKey)(const struct HuksParamSet *paramSet, const struct HuksBlob *kdfKey,
        struct HuksBlob *derivedKey);
    int32_t (*Mac)(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
        const struct HuksBlob *srcData, struct HuksBlob *mac);
    int32_t (*UpgradeKey)(const struct HuksBlob *oldKey, const struct HuksParamSet *paramSet,
        struct HuksBlob *newKey);
    int32_t (*ExportChipsetPlatformPublicKey)(const struct HuksBlob *salt,
        enum HuksChipsetPlatformDecryptScene scene, struct HuksBlob *publicKey);
    int32_t (*GetErrorInfo)(struct HuksBlob *errorInfo);
    int32_t (*GetStatInfo)(struct HuksBlob *statInfo);
    int32_t (*GetVersion)(uint32_t *majorVer, uint32_t *minorVer);
    
    int32_t (*Encapsulate)(const struct HuksParamSet *paramSet,
        const struct HuksParamSet *sharedKeyParamSet,
        struct HuksEncapsulationResult *encapResult);
    int32_t (*Decapsulate)(const struct HuksParamSet *paramSet,
        const struct HuksParamSet *sharedKeyParamSet, const struct HuksBlob *encapsulatedData,
        struct HuksBlob *sharedSecret);
} HuksHdiWrapper;

int32_t HuksHdiWrapperV1_1_Init(void);
int32_t HuksHdiWrapperV1_2_Init(void);
int32_t HuksHdiWrapperV1_1_Destroy(void);
int32_t HuksHdiWrapperV1_2_Destroy(void);

struct HuksHdiWrapper *HuksHdiWrapperV1_1_Get(void);
struct HuksHdiWrapper *HuksHdiWrapperV1_2_Get(void);

#endif
