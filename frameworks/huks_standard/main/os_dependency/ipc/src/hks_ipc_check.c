/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "hks_ipc_check.h"

#include <stddef.h>

#include "hks_common_check.h"
#include "hks_client_ipc_serialization.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"

#define MIN_CERT_COUNT 3
#define MAX_CERT_COUNT 4

int32_t HksCheckIpcBlobAndParamSet(const struct HksBlob *blob, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlobAndParamSet(blob, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check blob or paramSet failed")

    if (blob->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (((sizeof(blob->size) + ALIGN_SIZE(blob->size) +
        ALIGN_SIZE(paramSet->paramSetSize)) > MAX_PROCESS_SIZE)) {
        HKS_LOG_E("ipc blob and paramSet check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcBlob(const struct HksBlob *blob)
{
    int32_t ret = CheckBlob(blob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check blob or paramSet failed")

    if ((sizeof(blob->size) + ALIGN_SIZE(blob->size) > MAX_PROCESS_SIZE)) {
        HKS_LOG_E("ipc blob check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcOptionalBlobAndParamSet(const struct HksBlob *blob,
    const struct HksParamSet *paramSet)
{
    if (blob == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (blob->data == NULL || blob->size == 0) {
        return HksCheckParamSetValidity(paramSet);
    }
    return HksCheckIpcBlobAndParamSet(blob, paramSet);
}

int32_t HksCheckIpcGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn)
{
    int32_t ret = HksCheckBlobAndParamSet(keyAlias, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSetIn failed")

    if ((keyAlias->size > MAX_PROCESS_SIZE) ||
        ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSetIn->paramSetSize) +
        sizeof(uint32_t)) > MAX_PROCESS_SIZE)) {
        HKS_LOG_E("ipc generate key check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksCheckIpcImportKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key)
{
    int32_t ret = HksCheckBlob2AndParamSet(keyAlias, key, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or key or paramSetIn failed")

    if ((keyAlias->size > MAX_PROCESS_SIZE) || (key->size > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSet->paramSetSize) +
        sizeof(key->size) + ALIGN_SIZE(key->size) > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret = HksCheckBlob3AndParamSet(keyAlias, wrappingKeyAlias, wrappedKeyData, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or wrappingKeyAlias or wrappedKeyData or paramSet failed")

    if ((keyAlias->size > MAX_PROCESS_SIZE) || (wrappingKeyAlias->size > MAX_PROCESS_SIZE) ||
        (wrappedKeyData->size > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
         sizeof(wrappingKeyAlias->size) + ALIGN_SIZE(wrappingKeyAlias->size) + ALIGN_SIZE(paramSet->paramSetSize) +
         sizeof(wrappedKeyData->size) + ALIGN_SIZE(wrappedKeyData->size)) > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlobAndParamSet(keyAlias, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSet failed")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
        ALIGN_SIZE(paramSet->paramSetSize)) > MAX_PROCESS_SIZE)) {
        HKS_LOG_E("ipc delete key check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcExportPublicKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key)
{
    int32_t ret = HksCheckBlob2AndParamSet(keyAlias, key, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or key or paramSetIn failed")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + sizeof(key->size) +
        ALIGN_SIZE(paramSet->paramSetSize)) > MAX_PROCESS_SIZE) {
        HKS_LOG_E("ipc export public key check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcGetKeyParamSet(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    struct HksParamSet *paramSetOut)
{
    int32_t ret = HksCheckBlobAndParamSet(keyAlias, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSetIn failed")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (paramSetOut->paramSetSize == 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + sizeof(paramSetOut->paramSetSize) +
        ALIGN_SIZE(paramSetIn->paramSetSize)) > MAX_PROCESS_SIZE) {
        HKS_LOG_E("ipc get key paramset check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlobAndParamSet(keyAlias, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSet failed")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
        ALIGN_SIZE(paramSet->paramSetSize)) > MAX_PROCESS_SIZE)) {
        HKS_LOG_E("ipc key exist check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, const struct HksBlob *agreedKey)
{
    int32_t ret = HksCheckBlob3AndParamSet(privateKey, peerPublicKey, agreedKey, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check key or paramSetIn failed")

    if ((privateKey->size > MAX_PROCESS_SIZE) || (peerPublicKey->size > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((ALIGN_SIZE(paramSet->paramSetSize) + sizeof(privateKey->size) + ALIGN_SIZE(privateKey->size) +
        sizeof(peerPublicKey->size) + ALIGN_SIZE(peerPublicKey->size) + sizeof(agreedKey->size) > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    const struct HksBlob *derivedKey)
{
    int32_t ret = HksCheckBlob2AndParamSet(mainKey, derivedKey, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check key or paramSetIn failed")

    if (mainKey->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if ((ALIGN_SIZE(paramSet->paramSetSize) + sizeof(mainKey->size) + ALIGN_SIZE(mainKey->size) +
        sizeof(derivedKey->size)) > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcGetKeyInfoList(const struct HksKeyInfo *keyInfoList, const struct HksParamSet *paramSet,
    uint32_t listCount)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize), HKS_ERROR_INVALID_ARGUMENT)

    enum {
        HKS_GET_KEY_LIST_MAX_COUNT = 2048U,
    };
    if (listCount == 0 || listCount > HKS_GET_KEY_LIST_MAX_COUNT) {
        HKS_LOG_E("invalid listCount %" LOG_PUBLIC "u", listCount);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (listCount > (MAX_PROCESS_SIZE - ALIGN_SIZE(paramSet->paramSetSize) -
        sizeof(uint32_t)) / (sizeof(uint32_t) + sizeof(uint32_t))) {
        HKS_LOG_E("ipc get key info check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < listCount; ++i) {
        if ((CheckBlob(&keyInfoList[i].alias) != HKS_SUCCESS) ||
            (keyInfoList[i].paramSet == NULL) || (keyInfoList[i].paramSet->paramSetSize == 0)) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    uint32_t keyInfoBufSize = sizeof(listCount);
    for (uint32_t i = 0; i < listCount; ++i) {
        if (IsAdditionOverflow(keyInfoBufSize, sizeof(keyInfoList[i].alias.size))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        keyInfoBufSize += sizeof(keyInfoList[i].alias.size);
        if ((IsAdditionOverflow(keyInfoList[i].alias.size, DEFAULT_ALIGN_MASK_SIZE)) ||
            (IsAdditionOverflow(keyInfoList[i].paramSet->paramSetSize, DEFAULT_ALIGN_MASK_SIZE))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (IsAdditionOverflow(keyInfoBufSize, ALIGN_SIZE(keyInfoList[i].alias.size))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        keyInfoBufSize += ALIGN_SIZE(keyInfoList[i].alias.size);
        if (IsAdditionOverflow(keyInfoBufSize, ALIGN_SIZE(keyInfoList[i].paramSet->paramSetSize))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        keyInfoBufSize += ALIGN_SIZE(keyInfoList[i].paramSet->paramSetSize);
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcCertificateChain(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksCertChain *certChain)
{
    if ((certChain->certs == NULL) || (certChain->certsCount < MIN_CERT_COUNT) ||
        (certChain->certsCount > MAX_CERT_COUNT)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_IF_NOT_SUCC_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize), HKS_ERROR_INVALID_ARGUMENT)
    if ((keyAlias->size > MAX_PROCESS_SIZE) ||
        ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
        ALIGN_SIZE(paramSet->paramSetSize)) > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    uint32_t certBufSize = sizeof(certChain->certsCount);
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        if (IsAdditionOverflow(certBufSize, sizeof(certChain->certs[i].size))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        certBufSize += sizeof(certChain->certs[i].size);

        if (IsAdditionOverflow(certChain->certs[i].size, DEFAULT_ALIGN_MASK_SIZE)) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (IsAdditionOverflow(certBufSize, ALIGN_SIZE(certChain->certs[i].size))) {
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        certBufSize += ALIGN_SIZE(certChain->certs[i].size);
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcListAliases(const struct HksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize), HKS_ERROR_INVALID_ARGUMENT)

    if ((ALIGN_SIZE(paramSet->paramSetSize) > MAX_PROCESS_SIZE)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcRenameKeyAlias(const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias)
{
    int32_t ret = HksCheckBlob2AndParamSet(oldKeyAlias, newKeyAlias, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSet failed")

    if ((MAX_PROCESS_SIZE - sizeof(oldKeyAlias->size) - ALIGN_SIZE(oldKeyAlias->size) -
        sizeof(newKeyAlias->size) - ALIGN_SIZE(newKeyAlias->size) < ALIGN_SIZE(paramSet->paramSetSize))) {
        HKS_LOG_E("ipc rename key alias check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcChangeStorageLevel(const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *destParamSet)
{
    int32_t ret = HksCheckBlobAndParamSet2(keyAlias, srcParamSet, destParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or paramSet failed")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(srcParamSet->paramSetSize) +
        ALIGN_SIZE(destParamSet->paramSetSize)) > MAX_PROCESS_SIZE) {
        HKS_LOG_E("ipc change storage level check size failed");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t HksCheckIpcWrapKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappedKey)
{
    int32_t ret = HksCheckBlob2AndParamSet(keyAlias, wrappedKey, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or wrappedkey or paramSet fail")

    if (keyAlias->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
        ALIGN_SIZE(paramSet->paramSetSize) + sizeof(wrappedKey->size)) > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksCheckIpcUnwrapKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappedKey)
{
    int32_t ret = HksCheckBlob2AndParamSet(keyAlias, wrappedKey, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check keyAlias or wrappedkey or paramSet fail")

    if (keyAlias->size > MAX_PROCESS_SIZE || wrappedKey->size > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if ((sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSet->paramSetSize) +
        sizeof(wrappedKey->size) + ALIGN_SIZE(keyAlias->size)) > MAX_PROCESS_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}
