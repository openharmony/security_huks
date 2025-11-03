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

#include "hks_client_ipc_serialization.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type_enum.h"
#include "securec.h"

#define NUM_TWO        2

static const uint8_t BASE64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int32_t CopyUint32ToBuffer(uint32_t value, const struct HksBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) || ((destBlob->size - *destOffset) < sizeof(value))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &value,
        sizeof(value)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")
    *destOffset += sizeof(value);

    return HKS_SUCCESS;
}

static int32_t CopyBlobToBuffer(const struct HksBlob *blob, const struct HksBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) ||
        ((destBlob->size - *destOffset) < (sizeof(blob->size) + ALIGN_SIZE(blob->size)))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &(blob->size),
        sizeof(blob->size)), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")
    *destOffset += sizeof(blob->size);

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data,
        blob->size), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!")
    *destOffset += ALIGN_SIZE(blob->size);

    return HKS_SUCCESS;
}

static int32_t CopyParamSetToBuffer(const struct HksParamSet *paramSet,
    const struct HksBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) || (destBlob->size - *destOffset < ALIGN_SIZE(paramSet->paramSetSize))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, paramSet,
        paramSet->paramSetSize), HKS_ERROR_INSUFFICIENT_MEMORY, "copy destBlob data failed!");
    *destOffset += ALIGN_SIZE(paramSet->paramSetSize);

    return HKS_SUCCESS;
}

static int32_t GetUint32FromBuffer(uint32_t *value, const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || (srcBlob->size - *srcOffset < sizeof(*value))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    *value = *((uint32_t *)(srcBlob->data + *srcOffset));
    *srcOffset += sizeof(*value);
    return HKS_SUCCESS;
}

static int32_t GetBlobFromBuffer(struct HksBlob *blob, const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(blob->size))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t size = *((uint32_t *)(srcBlob->data + *srcOffset));
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(size, DEFAULT_ALIGN_MASK_SIZE), HKS_ERROR_INVALID_ARGUMENT)
    if (ALIGN_SIZE(size) > (srcBlob->size - *srcOffset - sizeof(blob->size))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    blob->size = size;
    *srcOffset += sizeof(blob->size);
    blob->data = (uint8_t *)(srcBlob->data + *srcOffset);
    *srcOffset += ALIGN_SIZE(blob->size);

    return HKS_SUCCESS;
}

static int32_t GetParamSetFromBuffer(struct HksParamSet **paramSet,
    const struct HksBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(struct HksParamSet))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    *paramSet = (struct HksParamSet *)(srcBlob->data + *srcOffset);
    HKS_IF_TRUE_RETURN(IsAdditionOverflow((*paramSet)->paramSetSize, DEFAULT_ALIGN_MASK_SIZE),
        HKS_ERROR_INVALID_ARGUMENT)
    if (ALIGN_SIZE((*paramSet)->paramSetSize) > (srcBlob->size - *srcOffset)) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    *srcOffset += ALIGN_SIZE((*paramSet)->paramSetSize);

    return HKS_SUCCESS;
}

int32_t HksUKeyGeneralPack(const struct HksBlob *blob, const struct HksParamSet *paramSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(blob, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy blob failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return HKS_SUCCESS;
}

int32_t HksUkeyBlob2ParamSetPack(const struct HksBlob *blob1, const struct HksBlob *blob2,
    const struct HksParamSet *paramSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret;
    do {
        ret = CopyBlobToBuffer(blob1, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy blob1 failed");

        ret = CopyBlobToBuffer(blob2, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy blob2 failed");

        ret = CopyParamSetToBuffer(paramSet, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy paramSet failed");
    } while (0);
    return ret;
}

int32_t HksGenerateKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, const struct HksBlob *keyOut)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(paramSetIn, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSetIn failed")
    return CopyUint32ToBuffer(keyOut->size, destData, &offset);
}

int32_t HksImportKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return CopyBlobToBuffer(key, destData, &offset);
}

int32_t HksImportWrappedKeyPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyBlobToBuffer(wrappingKeyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy wrappingKeyAlias failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return CopyBlobToBuffer(wrappedKeyData, destData, &offset);
}

int32_t HksClearPinAuthStatePack(const struct HksBlob *index, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(index, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    return HKS_SUCCESS;
}

int32_t HksDeleteKeyPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return HKS_SUCCESS;
}

int32_t HksExportPublicKeyPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyUint32ToBuffer(key->size, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keysize failed")
    return CopyParamSetToBuffer(paramSet, destData, &offset);
}

int32_t HksGetKeyParamSetPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *keyOut, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyUint32ToBuffer(keyOut->size, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyOutSize failed")
    return CopyParamSetToBuffer(paramSet, destData, &offset);
}

int32_t HksKeyExistPack(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return HKS_SUCCESS;
}

int32_t HksOnceParamPack(struct HksBlob *destData, const struct HksBlob *key, const struct HksParamSet *paramSet,
    uint32_t *offset)
{
    int32_t ret = CopyBlobToBuffer(key, destData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy key failed")

    return CopyParamSetToBuffer(paramSet, destData, offset);
}

int32_t HksOnceDataPack(struct HksBlob *destData, const struct HksBlob *inputData, const struct HksBlob *rsvData,
    const struct HksBlob *outputData, uint32_t *offset)
{
    int32_t ret = CopyBlobToBuffer(inputData, destData, offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy inputData failed")

    if (rsvData != NULL) {
        ret = CopyBlobToBuffer(rsvData, destData, offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy rsvData failed")
    }

    if (outputData != NULL) {
        ret = CopyUint32ToBuffer(outputData->size, destData, offset);
    }
    return ret;
}

int32_t HksAgreeKeyPack(struct HksBlob *destData, const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, const struct HksBlob *agreedKey)
{
    uint32_t offset = 0;
    int32_t ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")

    ret = CopyBlobToBuffer(privateKey, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy privateKey failed")

    ret = CopyBlobToBuffer(peerPublicKey, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy peerPublicKey failed")
    return CopyUint32ToBuffer(agreedKey->size, destData, &offset);
}

int32_t HksDeriveKeyPack(struct HksBlob *destData, const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    const struct HksBlob *derivedKey)
{
    uint32_t offset = 0;
    int32_t ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")

    ret = CopyBlobToBuffer(kdfKey, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy kdfKey failed")
    return CopyUint32ToBuffer(derivedKey->size, destData, &offset);
}

int32_t HksGetKeyInfoListPack(const struct HksParamSet *paramSet, const struct HksKeyInfo *keyInfoList,
    struct HksBlob *destData, uint32_t listCount)
{
    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(listCount, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy listCount failed")

    for (uint32_t i = 0; i < listCount; ++i) {
        ret = CopyUint32ToBuffer(keyInfoList[i].alias.size, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy alias failed")

        ret = CopyUint32ToBuffer(keyInfoList[i].paramSet->paramSetSize, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSetSize failed")
    }

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return HKS_SUCCESS;
}

int32_t HksGetKeyInfoListUnpackFromService(const struct HksBlob *srcData, uint32_t *listCount,
    struct HksKeyInfo *keyInfoList)
{
    uint32_t offset = 0;
    uint32_t countFromBuffer;
    int32_t ret = GetUint32FromBuffer(&countFromBuffer, srcData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get listCount failed")

    HKS_IF_TRUE_LOGE_RETURN(countFromBuffer > *listCount, HKS_ERROR_INVALID_ARGUMENT,
        "listCount from buffer is invalid")
    *listCount = countFromBuffer;

    struct HksBlob alias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    for (uint32_t i = 0; i < countFromBuffer; ++i) {
        ret = GetBlobFromBuffer(&alias, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get alias failed")

        HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(keyInfoList[i].alias.data, keyInfoList[i].alias.size, alias.data,
            alias.size), ret, "memcpy alias failed")
        keyInfoList[i].alias.size = alias.size;

        ret = GetParamSetFromBuffer(&paramSet, srcData, &offset);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get paramSet failed")

        HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(keyInfoList[i].paramSet, keyInfoList[i].paramSet->paramSetSize, paramSet,
            paramSet->paramSetSize), ret, "memcpy paramSet failed")

        ret = HksFreshParamSet(keyInfoList[i].paramSet, false);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "FreshParamSet fail, ret = %" LOG_PUBLIC "d", ret)
    }

    return HKS_SUCCESS;
}

int32_t HksCertificateChainPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *certChainBlob)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(paramSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")

    return CopyUint32ToBuffer(certChainBlob->size, destData, &offset);
}

static int32_t Base64Encode(const uint8_t *srcData, const uint32_t srcDataSize,
    uint8_t *outData, const uint32_t outDataSize)
{
    /*
     * outDataSize is already calculated on the outside.
     * Base64 encode like this:
     * <------------ byte ------------>
     * <------><-src1-><-src2-><-src3->
     * +------------------------------+
     * |      24      16      08      |
     * +------------------------------+
     *         <out1><out2><out3><out4>
     */
    uint32_t j = 0;
    uint32_t i = 0;
    while (i < srcDataSize) {
        uint32_t a = (i < srcDataSize) ? (uint8_t)srcData[i] : 0;
        ++i;
        uint32_t b = (i < srcDataSize) ? (uint8_t)srcData[i] : 0;
        ++i;
        uint32_t c = (i < srcDataSize) ? (uint8_t)srcData[i] : 0;
        ++i;
        /* srcData each character takes up 8 bits. 1, 2 and 3 is offset */
        uint32_t byte = (a << (8 * 2)) + (b << (8 * 1)) + (c << (8 * 0));

        /* outData each character takes up 6 bits */
        outData[j++] = BASE64_TABLE[(byte >> (6 * 3)) & 0b00111111]; /* 3 and 6 is offset */
        outData[j++] = BASE64_TABLE[(byte >> (6 * 2)) & 0b00111111]; /* 2 and 6 is offset */
        outData[j++] = BASE64_TABLE[(byte >> (6 * 1)) & 0b00111111]; /* 1 and 6 is offset */
        outData[j++] = BASE64_TABLE[(byte >> (6 * 0)) & 0b00111111]; /* 0 and 6 is offset */
    }

    const int32_t padding = srcDataSize % 3; /* 3 in each group */
    if (padding == 0) {
        return HKS_SUCCESS;
    } else {
        outData[outDataSize - 1] = '='; /* 1: padding last character with '=' */
    }
    if (padding == 1) {
        outData[outDataSize - 2] = '='; /* 2: padding penultimate character with '=' */
    }

    return HKS_SUCCESS;
}

static int32_t CheckAndCalculateSize(const uint32_t inSize, const uint32_t extraSize, uint32_t *outSize)
{
    /*
     * 2: fill it up to a multiple of three
     * 3 and 4: every three original characters is converted to four base64 characters
     */
    if (inSize > UINT32_MAX - NUM_TWO) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    /* 3 and 4: every three original characters is converted to four base64 characters */
    if (((inSize + 2) / 3) > (UINT32_MAX / 4)) { // 2: fill it up to a multiple of three
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    /* 3 and 4: every three original characters is converted to four base64 characters */
    if ((((inSize + 2) / 3) * 4) > UINT32_MAX - extraSize) { // 2: fill it up to a multiple of three
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    /* 3 and 4: every three original characters is converted to four base64 characters */
    *outSize = (((inSize + 2) / 3) * 4) + extraSize; // 2: fill it up to a multiple of three
    return HKS_SUCCESS;
}

int32_t EncodeCertChain(const struct HksBlob *inBlob, struct HksBlob *outBlob)
{
    const char begin[] = "-----BEGIN CERTIFICATE-----\n";
    const char end[] = "\n-----END CERTIFICATE-----";

    const uint32_t beginLen = strlen(begin);
    const uint32_t endLen = strlen(end);

    uint32_t tmpSize;
    int32_t ret = CheckAndCalculateSize(inBlob->size, beginLen + endLen, &tmpSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check inBlob size fail")

    struct HksBlob tmpBlob = { tmpSize, NULL };
    tmpBlob.data = (uint8_t *)HksMalloc(tmpSize);
    HKS_IF_NULL_LOGE_RETURN(tmpBlob.data, HKS_ERROR_MALLOC_FAIL, "malloc certEncoded fail")

    do {
        if (memcpy_s(tmpBlob.data, tmpSize, begin, beginLen) != EOK) {
            HKS_LOG_E("memcpy_s cert begin fail");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        if (memcpy_s(tmpBlob.data + tmpSize - endLen, endLen, end, endLen) != EOK) {
            HKS_LOG_E("memcpy_s cert end fail");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        ret = Base64Encode(inBlob->data, inBlob->size, tmpBlob.data + beginLen, tmpSize - beginLen - endLen);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Base64Encode fail")

        if (memcpy_s(outBlob->data, outBlob->size, tmpBlob.data, tmpBlob.size) != EOK) {
            HKS_LOG_E("copy certs encoded fail");
            ret = HKS_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        outBlob->size = tmpBlob.size;
    } while (0);

    HKS_FREE(tmpBlob.data);
    return ret;
}

int32_t HksCertificateChainUnpackFromService(const struct HksBlob *srcData, bool needEncode,
    struct HksCertChain *certChain)
{
    if (srcData->size < sizeof(certChain->certsCount)) {
        HKS_LOG_E("invalid certs buffer");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    uint32_t certsCount = *(uint32_t *)(srcData->data);
    if (certsCount > certChain->certsCount) {
        HKS_LOG_E("not enough output certs, real count %" LOG_PUBLIC "u, output count %" LOG_PUBLIC "u",
            certsCount, certChain->certsCount);
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    uint32_t offset = sizeof(certsCount);

    struct HksBlob tmp = { 0, NULL };
    for (uint32_t i = 0; i < certsCount; ++i) {
        HKS_IF_NOT_SUCC_LOGE_RETURN(GetBlobFromBuffer(&tmp, srcData, &offset),
            HKS_ERROR_IPC_MSG_FAIL, "get certs %" LOG_PUBLIC "d fail", i)
        HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(certChain->certs[i].data, certChain->certs[i].size, tmp.data, tmp.size),
            HKS_ERROR_INSUFFICIENT_DATA, "copy certs %" LOG_PUBLIC "d fail", i)

        if (needEncode) {
            struct HksBlob inBlob = { tmp.size, certChain->certs[i].data };
            int32_t ret = EncodeCertChain(&inBlob, &certChain->certs[i]);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "EncodeCertChain fail, ret = %" LOG_PUBLIC "d", ret)
        } else {
            certChain->certs[i].size = tmp.size;
        }
    }
    certChain->certsCount = certsCount;
    return HKS_SUCCESS;
}

int32_t HksParamsToParamSet(struct HksParam *params, uint32_t cnt, struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;

    int32_t ret = HksInitParamSet(&newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init param set failed")

    do {
        uint8_t tmpData = 0;
        struct HksBlob tmpBlob = { sizeof(tmpData), &tmpData };

        for (uint32_t i = 0; i < cnt; ++i) {
            if ((GetTagType(params[i].tag) == HKS_TAG_TYPE_BYTES) &&
                (params[i].blob.size == 0 || params[i].blob.data == NULL)) {
                params[i].tag += HKS_PARAM_BUFFER_NULL_INTERVAL;
                params[i].blob = tmpBlob;
            }
        }
        ret = HksAddParams(newParamSet, params, cnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add in params failed")

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset failed!")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;

    return ret;
}

static int32_t UnpackInt32FromBuffer(const struct HksBlob *srcBlob, uint32_t *offset, int32_t *out)
{
    if ((*offset > srcBlob->size) || (srcBlob->size - *offset < sizeof(int32_t))) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    *out = *((int32_t *)(srcBlob->data + *offset));
    *offset += sizeof(int32_t);
    return HKS_SUCCESS;
}

static int32_t UnpackBlobFromBuffer(const struct HksBlob *srcBlob, uint32_t *offset, struct HksBlob *out)
{
    struct HksBlob view = { 0, NULL };
    int32_t ret = GetBlobFromBuffer(&view, srcBlob, offset);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    out->size = view.size;
    if (view.size == 0) {
        out->data = NULL;
        return HKS_SUCCESS;
    }
    out->data = (uint8_t *)HksMalloc(view.size);
    if (out->data == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(out->data, out->size, view.data, view.size) != EOK) {
        HKS_FREE(out->data);
        out->data = NULL;
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    return HKS_SUCCESS;
}

static int32_t UnpackExtCertInfoFromBuffer(const struct HksBlob *srcBlob, uint32_t *offset,
    struct HksExtCertInfo *certInfo)
{
    int32_t ret = UnpackInt32FromBuffer(srcBlob, offset, &certInfo->purpose);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = UnpackBlobFromBuffer(srcBlob, offset, &certInfo->index);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = UnpackBlobFromBuffer(srcBlob, offset, &certInfo->cert);
    return ret;
}

int32_t HksCertificatesUnpackFromService(const struct HksBlob *srcBlob, struct HksExtCertInfoSet *destData)
{
    HKS_IF_TRUE_RETURN(srcBlob == NULL || destData == NULL, HKS_ERROR_INVALID_ARGUMENT);
    HKS_IF_TRUE_RETURN(srcBlob->size == 0, HKS_SUCCESS);

    uint32_t offset = 0;
    uint32_t cnt = 0;
    int32_t ret = GetUint32FromBuffer(&cnt, srcBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get cnt failed");

    HKS_IF_NOT_TRUE_RETURN(cnt <= HKS_MAX_CERT_COUNT, HKS_ERROR_BUFFER_TOO_SMALL);
    HKS_IF_TRUE_RETURN(cnt == 0, HKS_SUCCESS);

    struct HksExtCertInfo *certs = (struct HksExtCertInfo *)HksMalloc(sizeof(struct HksExtCertInfo) * cnt);
    HKS_IF_NULL_LOGE_RETURN(certs, HKS_ERROR_MALLOC_FAIL, "malloc certs array fail");

    if (memset_s(certs, sizeof(struct HksExtCertInfo) * cnt, 0, sizeof(struct HksExtCertInfo) * cnt) != EOK) {
        HKS_LOG_E("memset_s certs array fail");
        HKS_FREE(certs);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    for (uint32_t i = 0; i < cnt; ++i) {
        ret = UnpackExtCertInfoFromBuffer(srcBlob, &offset, &certs[i]);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("unpack cert info fail i=%" LOG_PUBLIC "u, ret=%d", i, ret);
            struct HksExtCertInfoSet tmp = { i, certs };
            HksFreeExtCertSet(&tmp);
            return ret;
        }
    }

    destData->count = cnt;
    destData->certs = certs;
    return HKS_SUCCESS;
}

int32_t HksRemotePropertyUnpackFromService(const struct HksBlob *srcBlob, struct HksParamSet **propertySetOut)
{
    int32_t ret;
    int32_t returnResult;
    uint32_t offset = 0;

    ret = UnpackInt32FromBuffer(srcBlob, &offset, &returnResult);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "UnpackInt32FromBuffer fail")

    struct HksParamSet *paramSetView = NULL;

    if (returnResult != 0) {
        ret = HUKS_ERR_CODE_DEPENDENT_MODULES_ERROR;
        HKS_LOG_E("remote property get failed, returnResult=%" LOG_PUBLIC "d", returnResult);
    }

    if (offset == srcBlob->size) {
        return ret;
    }

    ret = GetParamSetFromBuffer(&paramSetView, srcBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetParamSetFromBuffer fail")

    ret = HksGetParamSet(paramSetView, paramSetView->paramSetSize, propertySetOut);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksGetParamSet fail")

    return ret;
}

int32_t HksListAliasesPack(const struct HksParamSet *srcParamSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret = CopyParamSetToBuffer(srcParamSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet failed")
    return HKS_SUCCESS;
}

int32_t HksListAliasesUnpackFromService(const struct HksBlob *srcBlob, struct HksKeyAliasSet **destData)
{
    HKS_IF_TRUE_RETURN(srcBlob->size == 0, HKS_SUCCESS)
    int32_t ret = 0;
    uint32_t offset = 0;
    uint32_t cntFromBuffer;

    ret = GetUint32FromBuffer(&cntFromBuffer, srcBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get cnt failed")
    HKS_IF_NOT_TRUE_RETURN((cntFromBuffer <= HKS_MAX_KEY_ALIAS_COUNT), HKS_ERROR_BUFFER_TOO_SMALL);

    struct HksKeyAliasSet *tempAliasSet = (struct HksKeyAliasSet *)(HksMalloc(sizeof(struct HksKeyAliasSet)));
    HKS_IF_NULL_LOGE_RETURN(tempAliasSet, HKS_ERROR_MALLOC_FAIL, "malloc HksKeyAliasSet fail")

    tempAliasSet->aliasesCnt = cntFromBuffer;
    struct HksBlob tmpBlob = { 0, NULL };
    do {
        tempAliasSet->aliases = (struct HksBlob *)(HksMalloc(cntFromBuffer * sizeof(struct HksBlob)));
        if (tempAliasSet->aliases == NULL) {
            HKS_LOG_E("malloc HksKeyAliasSet aliases fail");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        for (uint32_t i = 0; i < cntFromBuffer; ++i) {
            ret = GetBlobFromBuffer(&tmpBlob, srcBlob, &offset);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get aliases %" LOG_PUBLIC "d fail", i)

            tempAliasSet->aliases[i].size = tmpBlob.size;
            tempAliasSet->aliases[i].data = (uint8_t *)HksMalloc(tempAliasSet->aliases[i].size);
            if (tempAliasSet->aliases[i].data == NULL) {
                HKS_LOG_E("malloc alias %" LOG_PUBLIC "d fail", i);
                ret = HKS_ERROR_MALLOC_FAIL;
                break;
            }
            if (memcpy_s(tempAliasSet->aliases[i].data, tempAliasSet->aliases[i].size, tmpBlob.data, tmpBlob.size)) {
                HKS_LOG_E("copy blob %" LOG_PUBLIC "d fail", i);
                ret = HKS_ERROR_BUFFER_TOO_SMALL;
                break;
            }
        }
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeKeyAliasSet(tempAliasSet);
        return ret;
    }
    *destData = tempAliasSet;
    return ret;
}

int32_t HksRenameKeyAliasPack(const struct HksBlob *oldKeyAlias, const struct HksBlob *newKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *destData)
{
    uint32_t offset = 0;
    int32_t ret;
    do {
        ret = CopyBlobToBuffer(oldKeyAlias, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy oldKeyAlias failed");

        ret = CopyBlobToBuffer(newKeyAlias, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy newKeyAlias failed");

        ret = CopyParamSetToBuffer(paramSet, destData, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy paramSet failed");
    } while (0);
    return ret;
}

int32_t HksChangeStorageLevelPack(struct HksBlob *destData, const struct HksBlob *keyAlias,
    const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias failed")

    ret = CopyParamSetToBuffer(srcParamSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy srcParamSet failed")

    ret = CopyParamSetToBuffer(destParamSet, destData, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy destParamSet failed")
    return HKS_SUCCESS;
}

int32_t HksWrapKeyPack(struct HksBlob *inBlob, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *wrappedKey)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, inBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias fail")

    ret = CopyParamSetToBuffer(paramSet, inBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet fail")

    return CopyUint32ToBuffer(wrappedKey->size, inBlob, &offset);
}

int32_t HksUnwrapKeyPack(struct HksBlob *inBlob, const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappedKey)
{
    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(keyAlias, inBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy keyAlias fail")

    ret = CopyParamSetToBuffer(paramSet, inBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy paramSet fail")

    ret = CopyBlobToBuffer(wrappedKey, inBlob, &offset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy wrappedKey fail")

    return HKS_SUCCESS;
}
