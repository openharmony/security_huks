/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HUKS_HAL_INTERFACES
#define HUKS_HAL_INTERFACES

#include <stdint.h>
#include <stdio.h>

#include "hks_config.h"
#include "hks_log.h"

struct HksHalDevice {
    int32_t (*ModuleInit)(void);

    int32_t (*Refresh)(void);

    int32_t (*GenerateKey)(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
            const struct HksBlob *keyIn, struct HksBlob *keyOut);

    int32_t (*ImportKey)(const struct HksBlob *keyAlias, const struct HksBlob *key, const struct HksParamSet *paramSet,
            struct HksBlob *keyOut);

    int32_t (*ImportWrappedKey)(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
            const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    int32_t (*ExportPublicKey)(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    int32_t (*Init)(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle);

    int32_t (*Update)(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
            struct HksBlob *outData);

    int32_t (*Finish)(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
            struct HksBlob *outData);

    int32_t (*Abort)(const struct HksBlob *handle, const struct HksParamSet *paramSet);

    int32_t (*GetKeyProperties)(const struct HksParamSet *paramSet, const struct HksBlob *key);

    int32_t (*AttestKey)(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain);

    int32_t (*GetAbility)(int funcType);

    int32_t (*GetHardwareInfo)(void);

    int32_t (*CalcMacHeader)(const struct HksParamSet *paramSet, const struct HksBlob *salt,
            const struct HksBlob *srcData, struct HksBlob *mac);

    int32_t (*UpgradeKeyInfo)(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo,
            struct HksBlob *keyOut);

    int32_t (*GenerateRandom)(const struct HksParamSet *paramSet, struct HksBlob *random);

    int32_t (*Sign)(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature);

    int32_t (*Verify)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, const struct HksBlob *signature);

    int32_t (*Encrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText);

    int32_t (*Decrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *cipherText, struct HksBlob *plainText);

    int32_t (*AgreeKey)(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
        const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

    int32_t (*DeriveKey)(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
        struct HksBlob *derivedKey);

    int32_t (*Mac)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *mac);
};

int32_t HksHalModuleInit(void);

int32_t HksHalRefresh(void);

int32_t HksHalGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut);

int32_t HksHalImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut);

int32_t HksHalImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

int32_t HksHalExportPublicKey(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut);

int32_t HksHalInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle);

int32_t HksHalUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksHalFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksHalAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);

int32_t HksHalGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key);

int32_t HksHalAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain);

int32_t HksHalGetAbility(int funcType);

int32_t HksHalGetHardwareInfo(void);

int32_t HksHalCalcMacHeader(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac);

int32_t HksHalUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo,
    struct HksBlob *keyOut);

int32_t HksHalGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random);

int32_t HksCreateHksHalDevice(void);

int32_t HksDestroyHksHalDevice(void);

int32_t HksHalProcessInit(uint32_t msgId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    uint64_t *operationHandle);

int32_t HksHalProcessMultiUpdate(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksHalProcessFinal(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData);

int32_t HksHalCalcHeaderMac(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac);

int32_t HksHalUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo, struct HksBlob *keyOut);

int32_t HksHalAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *certChain);

int32_t HksHalSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature);

int32_t HksHalVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature);

int32_t HksHalEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText);

int32_t HksHalDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText);

int32_t HksHalAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

int32_t HksHalDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey);

int32_t HksHalMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac);

#endif