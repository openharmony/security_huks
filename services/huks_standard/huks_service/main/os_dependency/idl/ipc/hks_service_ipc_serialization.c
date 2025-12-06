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

#include "hks_service_ipc_serialization.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#include <securec.h>

static int32_t CopyUint32ToBuffer(uint32_t value, const struct HksBlob *destBlob, uint32_t *destOffset)
{
    HKS_IF_TRUE_RETURN(*destOffset > destBlob->size, HKS_ERROR_BUFFER_TOO_SMALL)

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &(value), sizeof(value)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    *destOffset += sizeof(value);
    return HKS_SUCCESS;
}

static int32_t CopyInt32ToBuffer(int32_t value, const struct HksBlob *destBlob, uint32_t *destOffset)
{
    HKS_IF_TRUE_RETURN(*destOffset > destBlob->size, HKS_ERROR_BUFFER_TOO_SMALL)

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &(value), sizeof(value)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    *destOffset += sizeof(value);
    return HKS_SUCCESS;
}

static int32_t CopyBlobToBuffer(const struct HksBlob *blob, const struct HksBlob *destBlob, uint32_t *destOffset)
{
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(blob), HKS_ERROR_INVALID_ARGUMENT)

    HKS_IF_TRUE_RETURN((*destOffset > destBlob->size) ||
        (destBlob->size - *destOffset < sizeof(blob->size) + ALIGN_SIZE(blob->size)), HKS_ERROR_BUFFER_TOO_SMALL)

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &(blob->size),
        sizeof(blob->size)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")

    *destOffset += sizeof(blob->size);

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data,
        blob->size), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")

    *destOffset += ALIGN_SIZE(blob->size);
    return HKS_SUCCESS;
}

static int32_t CopyExtCertInfoToBuffer(const struct HksExtCertInfo *certInfo, const struct HksBlob *destBlob,
    uint32_t *destOffset)
{
    int32_t ret = CopyInt32ToBuffer(certInfo->purpose, destBlob, destOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyExtCertInfoToBuffer failed")

    ret = CopyBlobToBuffer(&certInfo->index, destBlob, destOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyBlobToBuffer failed")

    ret = CopyBlobToBuffer(&certInfo->cert, destBlob, destOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyBlobToBuffer failed")

    return ret;
}

static int32_t CopyParamSetToBuffer(const struct HksParamSet *paramSet,
    const struct HksBlob *destBlob, uint32_t *destOffset)
{
    HKS_IF_NULL_RETURN(paramSet, HKS_ERROR_INVALID_ARGUMENT)

    HKS_IF_TRUE_RETURN((*destOffset > destBlob->size) ||
        (destBlob->size - *destOffset < ALIGN_SIZE(paramSet->paramSetSize)), HKS_ERROR_BUFFER_TOO_SMALL)

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, paramSet, paramSet->paramSetSize) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    *destOffset += ALIGN_SIZE(paramSet->paramSetSize);
    return HKS_SUCCESS;
}

static int32_t GetUint32FromBuffer(uint32_t *value, const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    HKS_IF_TRUE_RETURN((*srcOffset > srcBlob->size) || (srcBlob->size - *srcOffset < sizeof(uint32_t)),
        HKS_ERROR_BUFFER_TOO_SMALL)

    if (memcpy_s(value, sizeof(*value), srcBlob->data + *srcOffset, sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("copy value failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    *srcOffset += sizeof(uint32_t);
    return HKS_SUCCESS;
}

int32_t GetBlobFromBuffer(struct HksBlob *blob, const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(uint32_t))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t size = *((uint32_t *)(srcBlob->data + *srcOffset));
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(size, DEFAULT_ALIGN_MASK_SIZE), HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_RETURN(ALIGN_SIZE(size) > srcBlob->size - *srcOffset - sizeof(uint32_t), HKS_ERROR_BUFFER_TOO_SMALL)

    blob->size = size;
    *srcOffset += sizeof(blob->size);
    blob->data = (uint8_t *)(srcBlob->data + *srcOffset);
    *srcOffset += ALIGN_SIZE(blob->size);
    return HKS_SUCCESS;
}

static int32_t GetParamSetFromBuffer(struct HksParamSet **paramSet,
    const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    HKS_IF_TRUE_RETURN(*srcOffset > srcBlob->size || ((srcBlob->size - *srcOffset) < sizeof(struct HksParamSet)),
        HKS_ERROR_INVALID_ARGUMENT)

    *paramSet = (struct HksParamSet*)(srcBlob->data + *srcOffset);
    HKS_IF_TRUE_RETURN(IsAdditionOverflow((*paramSet)->paramSetSize, DEFAULT_ALIGN_MASK_SIZE),
        HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_RETURN(ALIGN_SIZE((*paramSet)->paramSetSize) > (srcBlob->size - *srcOffset) ||
    HksFreshParamSet(*paramSet, false) != HKS_SUCCESS, HKS_ERROR_BUFFER_TOO_SMALL)

    *srcOffset += ALIGN_SIZE((*paramSet)->paramSetSize);
    return HKS_SUCCESS;
}

static int32_t GetKeyAndParamSetFromBuffer(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksParamSet **paramSet, uint32_t *offset)
{
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")

    ret = GetParamSetFromBuffer(paramSet, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "get paramSet failed")

    return ret;
}

static int32_t MallocBlobFromBuffer(const struct HksBlob *srcData, struct HksBlob *blob, uint32_t *offset)
{
    uint32_t blobSize = 0;
    int32_t ret = GetUint32FromBuffer(&blobSize, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get blobSize failed")

    HKS_IF_TRUE_LOGE_RETURN(IsInvalidLength(blobSize), HKS_ERROR_INVALID_ARGUMENT, "get blobSize failed")

    uint8_t *blobData = (uint8_t *)HksMalloc(blobSize);
    HKS_IF_NULL_RETURN(blobData, HKS_ERROR_MALLOC_FAIL)

    blob->data = blobData;
    blob->size = blobSize;
    return HKS_SUCCESS;
}

static int32_t MallocParamSetFromBuffer(const struct HksBlob *srcData, struct HksParamSet **paramSet, uint32_t *offset)
{
    uint32_t paramSetOutSize = 0;
    int32_t ret = GetUint32FromBuffer(&paramSetOutSize, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSetOutSize failed")

    HKS_IF_TRUE_LOGE_RETURN(IsInvalidLength(paramSetOutSize) || paramSetOutSize < sizeof(struct HksParamSet),
        HKS_ERROR_INVALID_ARGUMENT, "get paramSetOutSize failed")

    *paramSet = (struct HksParamSet *)HksMalloc(paramSetOutSize);
    HKS_IF_NULL_RETURN(*paramSet, HKS_ERROR_MALLOC_FAIL)

    (*paramSet)->paramSetSize = paramSetOutSize;
    return HKS_SUCCESS;
}

#ifdef HKS_UKEY_EXTENSION_CRYPTO
int32_t HksUKeyGeneralUnpack(const struct HksBlob *srcData, struct HksBlob *blob, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(blob, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    return HKS_SUCCESS;
}

int32_t HksUkeyBlob2ParamSetUnpack(const struct HksBlob *srcData, struct HksBlob *blob1,
    struct HksBlob *blob2, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret;
    do {
        ret = GetBlobFromBuffer(blob1, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get blob1 failed!");

        ret = GetBlobFromBuffer(blob2, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get blob2 failed!");

        ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get paramSet failed!");
    } while (0);
    return ret;
}
#endif

int32_t HksGenerateKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksParamSet **paramSetIn, struct HksBlob *keyOut)
{
    uint32_t offset = 0;
    int32_t ret = GetKeyAndParamSetFromBuffer(srcData, keyAlias, paramSetIn, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetKeyAndParamSetFromBuffer failed")

    uint32_t keyOutSize = 0;
    ret = GetUint32FromBuffer(&keyOutSize, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyOutSize failed")
    HKS_IF_TRUE_LOGE_RETURN(keyOutSize > MAX_OUT_BLOB_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "keyOutSize out of range %" LOG_PUBLIC "u", keyOutSize)
    HKS_IF_TRUE_RETURN(keyOutSize <= 0, HKS_SUCCESS)

    /* no allocate memory when keyOutSize is 0 */
    uint8_t *keyData = (uint8_t *)HksMalloc(keyOutSize);
    HKS_IF_NULL_RETURN(keyData, HKS_ERROR_MALLOC_FAIL)

    keyOut->data = keyData;
    keyOut->size = keyOutSize;

    return HKS_SUCCESS;
}

int32_t HksImportKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet,
    struct HksBlob *key)
{
    uint32_t offset = 0;
    int32_t ret = GetKeyAndParamSetFromBuffer(srcData, keyAlias, paramSet, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetKeyAndParamSetFromBuffer failed")

    return GetBlobFromBuffer(key, srcData, &offset);
}

int32_t HksImportWrappedKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksBlob *wrappingKeyAlias, struct HksParamSet **paramSet, struct HksBlob *wrappedKeyData)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")

    ret = GetBlobFromBuffer(wrappingKeyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get wrappingKeyAlias failed")

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    return GetBlobFromBuffer(wrappedKeyData, srcData, &offset);
}

int32_t HksClearPinAuthStateUnpack(const struct HksBlob *srcData, struct HksBlob *index)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(index, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get index failed")

    return HKS_SUCCESS;
}

int32_t HksDeleteKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    return HKS_SUCCESS;
}

int32_t HksExportPublicKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet,
    struct HksBlob *key)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")

    ret = MallocBlobFromBuffer(srcData, key, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc key data failed")
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")
    return ret;
}

int32_t HksGetKeyParamSetUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksParamSet **paramSetIn, struct HksParamSet **paramSetOut)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")

    ret = MallocParamSetFromBuffer(srcData, paramSetOut, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc paramSet failed")
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSetIn, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")
    return ret;
}

int32_t HksKeyExistUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    return HKS_SUCCESS;
}

static int32_t SignVerifyMacUnpack(const struct HksBlob *srcData, struct HksBlob *key, struct HksParamSet **paramSet,
    struct HksBlob *inputData, uint32_t *offset)
{
    int32_t ret = GetKeyAndParamSetFromBuffer(srcData, key, paramSet, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetKeyAndParamSetFromBuffer failed")

    ret = GetBlobFromBuffer(inputData, srcData, offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "get unsignedData failed")

    return ret;
}

int32_t HksSignUnpack(const struct HksBlob *srcData, struct HksBlob *key, struct HksParamSet **paramSet,
    struct HksBlob *unsignedData, struct HksBlob *signature)
{
    uint32_t offset = 0;
    int32_t ret = SignVerifyMacUnpack(srcData, key, paramSet, unsignedData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "SignVerifyMacUnpack failed")

    ret = MallocBlobFromBuffer(srcData, signature, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc signature data failed")

    return ret;
}

int32_t HksVerifyUnpack(const struct HksBlob *srcData, struct HksBlob *key, struct HksParamSet **paramSet,
    struct HksBlob *unsignedData, struct HksBlob *signature)
{
    uint32_t offset = 0;
    int32_t ret = SignVerifyMacUnpack(srcData, key, paramSet, unsignedData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "SignVerifyMacUnpack failed")

    return GetBlobFromBuffer(signature, srcData, &offset);
}

int32_t HksEncryptDecryptUnpack(const struct HksBlob *srcData, struct HksBlob *key,
    struct HksParamSet **paramSet, struct HksBlob *inputText, struct HksBlob *outputText)
{
    uint32_t offset = 0;
    int32_t ret = GetKeyAndParamSetFromBuffer(srcData, key, paramSet, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "getKeyAndParamSetFromBuffer failed")

    ret = GetBlobFromBuffer(inputText, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get inputText failed")

    ret = MallocBlobFromBuffer(srcData, outputText, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc outputText data failed")

    return ret;
}

int32_t HksAgreeKeyUnpack(const struct HksBlob *srcData, struct HksParamSet **paramSet, struct HksBlob *privateKey,
    struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    uint32_t offset = 0;
    int32_t ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    ret = GetBlobFromBuffer(privateKey, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get privateKey failed")

    ret = GetBlobFromBuffer(peerPublicKey, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get peerPublicKey failed")

    ret = MallocBlobFromBuffer(srcData, agreedKey, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc agreedKey data failed")

    return ret;
}

int32_t HksDeriveKeyUnpack(const struct HksBlob *srcData, struct HksParamSet **paramSet, struct HksBlob *kdfKey,
    struct HksBlob *derivedKey)
{
    uint32_t offset = 0;
    int32_t ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

    ret = GetBlobFromBuffer(kdfKey, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get kdfKey failed")

    ret = MallocBlobFromBuffer(srcData, derivedKey, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc derivedKey data failed")

    return ret;
}

int32_t HksHmacUnpack(const struct HksBlob *srcData, struct HksBlob *key, struct HksParamSet **paramSet,
    struct HksBlob *inputData, struct HksBlob *mac)
{
    uint32_t offset = 0;
    int32_t ret = SignVerifyMacUnpack(srcData, key, paramSet, inputData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "SignVerifyMacUnpack failed")

    ret = MallocBlobFromBuffer(srcData, mac, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc mac data failed")

    return ret;
}

static int32_t KeyInfoListInit(struct HksKeyInfo *keyInfoList, uint32_t listCount,
    const struct HksBlob *srcData, uint32_t *offset)
{
    uint32_t i = 0;
    int32_t ret = HKS_SUCCESS;
    for (; i < listCount; ++i) {
        ret = MallocBlobFromBuffer(srcData, &keyInfoList[i].alias, offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "malloc keyInfoList alias failed")

        ret = MallocParamSetFromBuffer(srcData, &keyInfoList[i].paramSet, offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "malloc keyInfoList paramSetSize failed")
    }

    HKS_IF_TRUE_RETURN(ret == HKS_SUCCESS, ret)
    for (uint32_t j = 0; j <= i; ++j) {
        HKS_FREE_BLOB(keyInfoList[j].alias);
        HKS_FREE(keyInfoList[j].paramSet);
    }
    return ret;
}

int32_t HksGetKeyInfoListUnpack(const struct HksBlob *srcData, struct HksParamSet **paramSet, uint32_t *listCount,
    struct HksKeyInfo **keyInfoList)
{
    uint32_t offset = 0;
    int32_t ret = GetUint32FromBuffer(listCount, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get count failed")

    enum {
        HKS_GET_KEY_LIST_MAX_COUNT = 2048U,
    };
    HKS_IF_TRUE_LOGE_RETURN(*listCount == 0 || *listCount > HKS_GET_KEY_LIST_MAX_COUNT, HKS_ERROR_INSUFFICIENT_MEMORY,
        "invalid listCount %" LOG_PUBLIC "u", *listCount)

    uint32_t keyInfoListSize = (*listCount) * sizeof(struct HksKeyInfo);
    HKS_IF_TRUE_LOGE_RETURN(IsInvalidLength(keyInfoListSize), HKS_ERROR_INSUFFICIENT_MEMORY,
        "keyInfoListSize too big %" LOG_PUBLIC "u", keyInfoListSize)

    *keyInfoList = (struct HksKeyInfo *)HksMalloc(keyInfoListSize);
    HKS_IF_NULL_LOGE_RETURN(*keyInfoList, HKS_ERROR_MALLOC_FAIL, "*keyInfoList is NULL")

    (void)memset_s(*keyInfoList, keyInfoListSize, 0, keyInfoListSize);

    ret = KeyInfoListInit(*keyInfoList, *listCount, srcData, &offset);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("KeyInfoListInit failed");
        HKS_FREE(*keyInfoList);
    }
    HKS_IF_TRUE_RETURN(offset == srcData->size, HKS_SUCCESS)

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")
    return ret;
}

int32_t HksParamSetPack(struct HksBlob *inBlob, const struct HksParamSet *paramSet)
{
    uint32_t offset = 0;
    return CopyParamSetToBuffer(paramSet, inBlob, &offset);
}

int32_t HksGetKeyInfoListPackFromService(struct HksBlob *destData, uint32_t listCount,
    const struct HksKeyInfo *keyInfoList)
{
    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(listCount, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyUint32ToBuffer failed")

    for (uint32_t i = 0; i < listCount; ++i) {
        ret = CopyBlobToBuffer(&keyInfoList[i].alias, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy alias failed")

        ret = CopyParamSetToBuffer(keyInfoList[i].paramSet, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    }

    return HKS_SUCCESS;
}

int32_t HksCertificateChainUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksParamSet **paramSet, struct HksBlob *certChainBlob)
{
    uint32_t offset = 0;
    int32_t ret = GetKeyAndParamSetFromBuffer(srcData, keyAlias, paramSet, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetKeyAndParamSetFromBuffer failed")

    ret = MallocBlobFromBuffer(srcData, certChainBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc certChainBlob data failed")

    return ret;
}

static int32_t GetNullBlobParam(const struct HksParamSet *paramSet, struct HksParamOut *outParams)
{
    HKS_IF_TRUE_LOGE_RETURN(GetTagType(outParams->tag) != HKS_TAG_TYPE_BYTES, HKS_ERROR_PARAM_NOT_EXIST,
        "get param tag[0x%" LOG_PUBLIC "x] from ipc buffer failed", outParams->tag)

    struct HksParam *param = NULL;
    int32_t ret = HksGetParam(paramSet, outParams->tag + HKS_PARAM_BUFFER_NULL_INTERVAL, &param);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param tag[0x%" LOG_PUBLIC "x] from ipc buffer failed",
        outParams->tag + HKS_PARAM_BUFFER_NULL_INTERVAL)

    outParams->blob->data = NULL;
    outParams->blob->size = 0;
    return HKS_SUCCESS;
}

static int32_t GetNormalParam(const struct HksParam *param, struct HksParamOut *outParams)
{
    switch (GetTagType(outParams->tag)) {
        case HKS_TAG_TYPE_INT:
            *(outParams->int32Param) = param->int32Param;
            break;
        case HKS_TAG_TYPE_UINT:
            *(outParams->uint32Param) = param->uint32Param;
            break;
        case HKS_TAG_TYPE_ULONG:
            *(outParams->uint64Param) = param->uint64Param;
            break;
        case HKS_TAG_TYPE_BOOL:
            *(outParams->boolParam) = param->boolParam;
            break;
        case HKS_TAG_TYPE_BYTES:
            *(outParams->blob) = param->blob;
            break;
        default:
            HKS_LOG_I("invalid tag type:%" LOG_PUBLIC "x", GetTagType(outParams->tag));
            return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksParamSetToParams(const struct HksParamSet *paramSet, struct HksParamOut *outParams, uint32_t cnt)
{
    struct HksParam *param = NULL;
    for (uint32_t i = 0; i < cnt; i++) {
        int32_t ret = HksGetParam(paramSet, outParams[i].tag, &param);
        if (ret == HKS_SUCCESS) {
            ret = GetNormalParam(param, &outParams[i]);
        } else {
            ret = GetNullBlobParam(paramSet, &outParams[i]);
        }
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param failed, ret = %" LOG_PUBLIC "d", ret)
    }
    return HKS_SUCCESS;
}

int32_t HksListAliasesUnpack(const struct HksBlob *srcData, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")
    return ret;
}

static int32_t HksCopyExtCertInfosAndCntToBlob(const struct HksExtCertInfo *srcCerts, uint32_t cnt,
    struct HksBlob *destBlob)
{
    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(cnt, destBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyUint32ToBuffer failed, ret = %" LOG_PUBLIC "d", ret)

    for (uint32_t i = 0; i < cnt; ++i) {
        ret = CopyExtCertInfoToBuffer(&srcCerts[i], destBlob, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyExtCertInfoToBuffer failed")
    }
    return HKS_SUCCESS;
}

static int32_t HksCopyBlobsAndCntToBlob(const struct HksBlob *srcBlob, uint32_t cnt, struct HksBlob *destBlob)
{
    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(cnt, destBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyUint32ToBuffer failed, ret = %" LOG_PUBLIC "d", ret)

    for (uint32_t i = 0; i < cnt; ++i) {
        ret = CopyBlobToBuffer(&srcBlob[i], destBlob, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy CopyBlobToBuffer failed")
    }
    return HKS_SUCCESS;
}

int32_t HksCertificatesPackFromService(const struct HksExtCertInfoSet *certInfoSet, struct HksBlob *destData)
{
    HKS_IF_TRUE_LOGE_RETURN(destData == NULL || destData->size != 0, HKS_ERROR_INVALID_ARGUMENT,
        "HksCertificatesPackFromService invalid param")
    HKS_IF_TRUE_RETURN(certInfoSet == NULL, HKS_SUCCESS)

    destData->size = sizeof(certInfoSet->count);
    for (uint32_t i = 0; i < certInfoSet->count; ++i) {
        const struct HksExtCertInfo *certInfo = &certInfoSet->certs[i];
        destData->size += sizeof(int32_t); /* purpose */
        destData->size += sizeof(certInfo->index.size) + ALIGN_SIZE(certInfo->index.size);
        destData->size += sizeof(certInfo->cert.size)  + ALIGN_SIZE(certInfo->cert.size);
    }
    destData->data = (uint8_t *)HksMalloc(destData->size);
    HKS_IF_NULL_RETURN(destData->data, HKS_ERROR_MALLOC_FAIL)

    return HksCopyExtCertInfosAndCntToBlob(certInfoSet->certs, certInfoSet->count, destData);
}

int32_t HksListAliasesPackFromService(const struct HksKeyAliasSet *aliasSet, struct HksBlob *destData)
{
    HKS_IF_TRUE_LOGE_RETURN(destData == NULL || destData->size != 0, HKS_ERROR_INVALID_ARGUMENT,
        "HksListAliasesPackFromService invalid param")
    HKS_IF_TRUE_RETURN(aliasSet == NULL || aliasSet->aliasesCnt == 0, HKS_SUCCESS)

    destData->size = sizeof(aliasSet->aliasesCnt);
    for (uint32_t i = 0; i < aliasSet->aliasesCnt; ++i) {
        destData->size += sizeof(aliasSet->aliases[i].size) + ALIGN_SIZE(aliasSet->aliases[i].size);
    }
    destData->data = (uint8_t *)HksMalloc(destData->size);
    HKS_IF_NULL_RETURN(destData->data, HKS_ERROR_MALLOC_FAIL)

    return HksCopyBlobsAndCntToBlob(aliasSet->aliases, aliasSet->aliasesCnt, destData);
}

int32_t HksRenameKeyAliasUnpack(const struct HksBlob *srcData, struct HksBlob *oldKeyAlias,
    struct HksBlob *newKeyAlias, struct HksParamSet **paramSet)
{
    uint32_t offset = 0;
    int32_t ret;
    do {
        ret = GetBlobFromBuffer(oldKeyAlias, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get oldKeyAlias failed!");

        ret = GetBlobFromBuffer(newKeyAlias, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get newKeyAlias failed!");

        ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get paramSet failed!");
    } while (0);
    return ret;
}

int32_t HksChangeStorageLevelUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias,
    struct HksParamSet **srcParamSet, struct HksParamSet **destParamSet)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias failed")

    ret = GetParamSetFromBuffer(srcParamSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get srcParamSet failed")

    ret = GetParamSetFromBuffer(destParamSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get destParamSet failed")

    return HKS_SUCCESS;
}

int32_t HksWrapKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet,
    struct HksBlob *wrappedKey)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias fail")

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet fail")

    ret = MallocBlobFromBuffer(srcData, wrappedKey, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "malloc wrappedKey fail")

    return ret;
}

int32_t HksUnwrapKeyUnpack(const struct HksBlob *srcData, struct HksBlob *keyAlias, struct HksParamSet **paramSet,
    struct HksBlob *wrappedKey)
{
    uint32_t offset = 0;
    int32_t ret = GetBlobFromBuffer(keyAlias, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get keyAlias fail")

    ret = GetParamSetFromBuffer(paramSet, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet fail")

    ret = GetBlobFromBuffer(wrappedKey, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE(ret, "get wrappedKey fail")

    return ret;
}
