/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_sm_import_wrap_key.h"
#include "securec.h"

#include <stdbool.h>
#include <stddef.h>

#if defined(HKS_SUPPORT_SM2_C) && defined(HKS_SUPPORT_SM3_C) && defined(HKS_SUPPORT_SM4_C)
#include "hks_ability.h"
#include "hks_base_check.h"
#include "hks_check_paramset.h"
#include "hks_client_service_adapter_common.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_crypto_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_core_service_key_generate.h"
#include "hks_core_service_key_operate_one_stage.h"
#include "hks_openssl_sm2.h"
#include "hks_openssl_sm4.h"
#include "hks_error_code.h"

#define HKS_PADDING_SUPPLENMENT 16

static const uint32_t g_validCipher[] = {
#ifdef HKS_SUPPORT_SM4_C
    HKS_ALG_SM4,
#endif
#ifdef HKS_SUPPORT_SM2_C
    HKS_ALG_SM2,
#endif
};

static void ClearAndFreeKeyBlob(struct HksBlob *blobData)
{
    if (blobData == NULL) {
        return;
    }
    if (blobData->data != NULL) {
        (void)memset_s(blobData->data, blobData->size, 0, blobData->size);
        HKS_FREE(blobData->data);
    }
}

static void ClearAndFreeWrappedBlob(struct HksSmWrappedKeyDataBlob *dataParams)
{
    if (dataParams == NULL) {
        return;
    }
    ClearAndFreeKeyBlob(&dataParams->originKey);
    ClearAndFreeKeyBlob(&dataParams->peerPublicKey);
    ClearAndFreeKeyBlob(&dataParams->kekAndSignData);
    ClearAndFreeKeyBlob(&dataParams->kekData);
    ClearAndFreeKeyBlob(&dataParams->signData);
    ClearAndFreeKeyBlob(&dataParams->deriveKekData1);
    ClearAndFreeKeyBlob(&dataParams->deriveKekData2);
}

static int32_t GetDataLenFromWrappedData(const struct HksBlob *wrappedKeyData,
    uint32_t partOffset, uint32_t totalBlobs, uint32_t *originDataLen)
{
    struct HksBlob originDataLenBlobPart = { 0, NULL };
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, partOffset, totalBlobs, &originDataLenBlobPart);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key material len failed!");

    if (originDataLenBlobPart.size != sizeof(uint32_t)) {
        HKS_LOG_E("len part is invalid!");
        return HKS_ERROR_INVALID_WRAPPED_FORMAT;
    }

    uint32_t dataSize = 0;
    (void)memcpy_s((uint8_t *)&dataSize, sizeof(uint32_t), originDataLenBlobPart.data, originDataLenBlobPart.size);
    if (dataSize > MAX_KEY_SIZE) {
        HKS_LOG_E("material size is invalid!");
        return HKS_ERROR_INVALID_WRAPPED_FORMAT;
    }

    *originDataLen = dataSize;
    return HKS_SUCCESS;
}

static int32_t GetPublicKeyAndSignDataLength(const struct HksBlob *wrappedKeyData, struct HksKeyNode *keyNode,
    struct HksSmWrappedKeyDataBlob *dataParams, uint32_t *partOffset)
{
    if ((dataParams == NULL) || (keyNode == NULL)) {
        HKS_LOG_E("invalid argument!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob peerPubKeyPart = { 0, NULL };
    uint32_t offset = *partOffset;
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++, HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS,
        &peerPubKeyPart);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get peer pub key failed!");

    ret = GetDataLenFromWrappedData(wrappedKeyData, offset++, HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS,
        &dataParams->signatureDataLength);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get sign data length failed!");
    if (peerPubKeyPart.size != 0) {
        ret = GetHksPubKeyInnerFormat(keyNode->paramSet, &peerPubKeyPart, &dataParams->peerPublicKey);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get peer pub key inner format failed!");
    }
    *partOffset = offset;
    return HKS_SUCCESS;
}

static int32_t AddDecryptKeyParamSetFromUnwrapSuite(const struct HksParamSet *inParamSet,
    struct HksParamSet *paramSet)
{
    struct HksParam decryptParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256 },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_NONE},
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
    };

    int32_t ret = HksAddParams(paramSet, decryptParams, sizeof(decryptParams) / sizeof(struct HksParam));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "unwrap suite add params failed.")

    uint32_t accessTagList[] = { HKS_TAG_ACCESS_TOKEN_ID, HKS_TAG_USER_ID, HKS_TAG_PROCESS_NAME };
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(accessTagList); ++i) {
        struct HksParam *tmpParam = NULL;
        ret = HksGetParam(inParamSet, accessTagList[i], &tmpParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "get param %" LOG_PUBLIC "u failed.", i)

        ret = HksAddParams(paramSet, tmpParam, 1);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "add param %" LOG_PUBLIC "u failed.", i)
    }
    return ret;
}

static int32_t GetSm2DecryptParamSet(const struct HksParamSet *inParamSet, struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init key param set fail!")

    ret = AddDecryptKeyParamSetFromUnwrapSuite(inParamSet, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("unwrap suite add params failed.");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("unwrap suite build params failed.");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    *outParamSet = paramSet;
    return HKS_SUCCESS;
}

static int32_t DecryptKekWithSm2(const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet,
    struct HksKeyNode *keyNode, struct HksSmWrappedKeyDataBlob *dataParams, uint32_t *partOffset)
{
    uint32_t offset = *partOffset;
    struct HksBlob kekEncDataPart = { 0, NULL };
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &kekEncDataPart);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get kek_enc data failed!");

    uint32_t kekOriginDataLen = 0;
    ret = GetDataLenFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &kekOriginDataLen);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get kek origin len failed!");

    struct HksBlob plainTextBlob = { 0, NULL };
    plainTextBlob.size = kekOriginDataLen + dataParams->signatureDataLength;
    uint8_t *kekBuffer = (uint8_t *)HksMalloc(plainTextBlob.size);
    HKS_IF_NULL_LOGE_RETURN(kekBuffer, HKS_ERROR_MALLOC_FAIL, "malloc kekBuffer memory failed!");
    plainTextBlob.data = kekBuffer;
    struct HksParamSet *decryptParamSet = NULL;
    struct HksBlob rawKey = { 0, NULL };
    struct HksUsageSpec *usageSpec = NULL;
    do {
        ret = GetSm2DecryptParamSet(paramSet, &decryptParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get decrypt param failed!")
        ret = HksGetRawKey(keyNode->paramSet, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "cipher get raw key failed!")
        ret = HksBuildCipherUsageSpec(decryptParamSet, false, &kekEncDataPart, &usageSpec);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build usage spec failed!")
        ret = HksCryptoHalDecrypt(&rawKey, usageSpec, &kekEncDataPart, &plainTextBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt data failed!")
    } while (0);
    HksFreeParamSet(&decryptParamSet);
    HksFreeUsageSpec(&usageSpec);
    ClearAndFreeKeyBlob(&rawKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get decrypt param failed!");
        ClearAndFreeKeyBlob(&plainTextBlob);
        return ret;
    }
    if (dataParams->signatureDataLength == 0) {
        dataParams->kekData.size = plainTextBlob.size;
        dataParams->kekData.data = plainTextBlob.data;
    } else {
        dataParams->kekAndSignData.size = plainTextBlob.size;
        dataParams->kekAndSignData.data = plainTextBlob.data;
    }
    *partOffset = offset;
    return HKS_SUCCESS;
}

static int32_t SplitKekAndSignData(struct HksSmWrappedKeyDataBlob *dataParams)
{
    struct HksBlob *kekAndSignBlob = &dataParams->kekAndSignData;
    uint32_t signDataLen = dataParams->signatureDataLength;
    struct HksBlob kekDataBlob = {0, NULL};
    struct HksBlob signatureDataBlob = {0, NULL};
    if (kekAndSignBlob->size < signDataLen) {
        HKS_LOG_E("sign data size is invalid!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    kekDataBlob.size = kekAndSignBlob->size - signDataLen;
    kekDataBlob.data = (uint8_t *)HksMalloc(kekDataBlob.size);
    HKS_IF_NULL_LOGE_RETURN(kekDataBlob.data, HKS_ERROR_MALLOC_FAIL, "malloc kekDataBlob memory failed!");
    int32_t ret = HKS_SUCCESS;
    do {
        (void)memcpy_s(kekDataBlob.data, kekDataBlob.size, kekAndSignBlob->data, kekDataBlob.size);
        if (signDataLen == 0) {
            break;
        }
        signatureDataBlob.size = signDataLen;
        signatureDataBlob.data = (uint8_t *)HksMalloc(signDataLen);
        if (signatureDataBlob.data == NULL) {
            HKS_LOG_E("malloc signatureDataBlob memory failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        (void)memcpy_s(signatureDataBlob.data, signatureDataBlob.size, kekAndSignBlob->data + kekDataBlob.size,
            signatureDataBlob.size);
    } while (0);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(signatureDataBlob.data);
        HKS_FREE(kekDataBlob.data);
        return ret;
    }
    dataParams->kekData.size = kekDataBlob.size;
    dataParams->kekData.data = kekDataBlob.data;
    dataParams->signData.size = signatureDataBlob.size;
    dataParams->signData.data = signatureDataBlob.data;
    return ret;
}

static int32_t VerifyKekBySm2(const struct HksSmWrappedKeyDataBlob *dataParams)
{
    struct HksParam verifyParams[] = {
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_SM2},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_SM2_KEY_SIZE_256},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SM3},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE},
    };

    struct HksParamSet *verifyParamSet = NULL;
    int32_t ret = HksInitParamSet(&verifyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init verify key param set failed!");

    ret = HksAddParams(verifyParamSet, verifyParams, sizeof(verifyParams) / sizeof(struct HksParam));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksAddParams failed!");
        HksFreeParamSet(&verifyParamSet);
        return ret;
    }
    ret = HksBuildParamSet(&verifyParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("unwrap suite build params failed.");
        HksFreeParamSet(&verifyParamSet);
        return ret;
    }
    struct HksUsageSpec usageSpec = { 0 };
    HksFillUsageSpec(verifyParamSet, &usageSpec);
    ret = HksCryptoHalVerify(&dataParams->peerPublicKey, &usageSpec, &dataParams->kekData, &dataParams->signData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCryptoHalVerify failed!");
    }

    HksFreeParamSet(&verifyParamSet);
    return ret;
}

static int32_t DeriveKeyBySm3(const struct HksBlob *srcData, const struct HksBlob *factor, struct HksBlob *deriveKey)
{
    struct HksBlob deriveBlob = { 0, NULL };
    deriveBlob.size = HKS_KEY_BYTES(HKS_SM4_KEY_SIZE_128);
    deriveBlob.data = (uint8_t *)HksMalloc(deriveBlob.size);
    HKS_IF_NULL_LOGE_RETURN(deriveBlob.data, HKS_ERROR_MALLOC_FAIL, "malloc deriveBlob memory failed!");

    struct HksKeyDerivationParam derParam = {
        .digestAlg = HKS_DIGEST_SM3,
        .info = *factor,
    };
    struct HksKeySpec derivationSpec = { HKS_ALG_GMKDF, HKS_KEY_BYTES(HKS_SM4_KEY_SIZE_128), &derParam };
    int32_t ret = HksCryptoHalDeriveKey(srcData, &derivationSpec, &deriveBlob);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(deriveBlob.data);
        HKS_LOG_E("derive key failed!");
        return ret;
    }
    deriveKey->size = deriveBlob.size;
    deriveKey->data = deriveBlob.data;
    return HKS_SUCCESS;
}

static int32_t DeriveKeyByFactor(const struct HksBlob *wrappedKeyData, struct HksSmWrappedKeyDataBlob *dataParams,
    uint32_t *partOffset)
{
    struct HksBlob *deriveKek1 = &dataParams->deriveKekData1;
    struct HksBlob *deriveKek2 = &dataParams->deriveKekData2;
    struct HksBlob factor1 = { 0, NULL };
    struct HksBlob factor2 = { 0, NULL };
    uint32_t offset = *partOffset;
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &factor1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get factor1 data failed!");

    ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++, HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &factor2);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get factor2 data failed!");
    do {
        ret = DeriveKeyBySm3(&dataParams->kekData, &factor1, deriveKek1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive kek1 data failed!") ;

        ret = DeriveKeyBySm3(&dataParams->kekData, &factor2, deriveKek2);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive kek2 data failed!") ;
    } while (0);

    if (ret != HKS_SUCCESS) {
        HKS_FREE(deriveKek1->data);
        HKS_FREE(deriveKek2->data);
        return ret;
    }
    *partOffset = offset;
    return HKS_SUCCESS;
}

static int32_t CompareWrapKeyHmac(const struct HksBlob *wrappedKeyData, struct HksSmWrappedKeyDataBlob *dataParams,
    struct HksBlob *kEncData, uint32_t *partOffset)
{
    struct HksBlob originKeyEncMac = { 0, NULL };
    uint32_t offset = *partOffset;
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &originKeyEncMac);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get originKeyEncMac data failed!");
    ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++, HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, kEncData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get kenc data failed!");

    struct HksBlob mac = { 0, NULL };
    mac.size = originKeyEncMac.size;
    mac.data = (uint8_t *)HksMalloc(mac.size);
    HKS_IF_NULL_LOGE_RETURN(mac.data, HKS_ERROR_MALLOC_FAIL, "malloc mac memory failed!");
    do {
        ret = HksCryptoHalHmac(&dataParams->deriveKekData2, HKS_DIGEST_SM3, kEncData, &mac);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "cal hmac value failed!")
        ret = HksMemCmp(originKeyEncMac.data, mac.data, mac.size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "compare kek enc data mac failed!")
    } while (0);
    HKS_FREE(mac.data);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("compare mac failed!");
        return ret;
    }
    *partOffset = offset;
    return ret;
}

static int32_t BuildDecryptUsageSpecOfSmUnwrap(const struct HksBlob *iv, struct HksUsageSpec *usageSpec)
{
    usageSpec->mode = HKS_MODE_CBC;
    usageSpec->padding = HKS_PADDING_PKCS7;
    usageSpec->digest = HKS_DIGEST_NONE;
    usageSpec->algType = HKS_ALG_SM4;

    struct HksCipherParam *cipherParam = (struct HksCipherParam *)HksMalloc(sizeof(struct HksCipherParam));
    HKS_IF_NULL_LOGE_RETURN(cipherParam, HKS_ERROR_MALLOC_FAIL, "build dec wrapped usage: cipherParam malloc failed!");

    cipherParam->iv = *iv;

    usageSpec->algParam = cipherParam;
    return HKS_SUCCESS;
}

static int32_t SubPaddingPlaintext(const struct HksBlob *srcData, struct HksBlob *outData, uint32_t subLength)
{
    uint8_t *mallocResultData = (uint8_t *)HksMalloc(subLength);
    HKS_IF_NULL_LOGE_RETURN(mallocResultData, HKS_ERROR_MALLOC_FAIL, "malloc mallocResultData memory failed!");
    (void)memcpy_s(mallocResultData, subLength, srcData->data, subLength);
    outData->size = subLength;
    outData->data = mallocResultData;
    return HKS_SUCCESS;
}

static int32_t DecryptImportedSmKey(const struct HksBlob *wrappedKeyData, struct HksSmWrappedKeyDataBlob *dataParams,
    struct HksBlob *kEncData, uint32_t *partOffset)
{
    uint32_t offset = *partOffset;
    struct HksBlob ivParam = { 0, NULL };
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &ivParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get ivParam data failed!");

    uint32_t keyMaterialSize = 0;
    ret = GetDataLenFromWrappedData(wrappedKeyData, offset++,
        HKS_IMPORT_WRAPPED_KEY_TOTAL_BLOBS, &keyMaterialSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get key material data failed!");

    struct HksBlob originKey = { 0, NULL };
    originKey.size = keyMaterialSize + HKS_PADDING_SUPPLENMENT;
    uint8_t *originKeyBuffer = (uint8_t *)HksMalloc(originKey.size);
    HKS_IF_NULL_LOGE_RETURN(originKeyBuffer, HKS_ERROR_MALLOC_FAIL, "malloc originKeyBuffer memory failed!");

    originKey.data = originKeyBuffer;
    struct HksUsageSpec *decOriginKeyUsageSpec = (struct HksUsageSpec *)HksMalloc(sizeof(struct HksUsageSpec));
    if (decOriginKeyUsageSpec == NULL) {
        HKS_LOG_E("malloc originKeyBuffer memory failed!");
        HKS_FREE(originKey.data);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(decOriginKeyUsageSpec, sizeof(struct HksUsageSpec), 0, sizeof(struct HksUsageSpec));
    ret = BuildDecryptUsageSpecOfSmUnwrap(&ivParam, decOriginKeyUsageSpec);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("build decrypt wrapped data origin key usageSpec failed!");
        HKS_FREE(originKey.data);
        HksFreeUsageSpec(&decOriginKeyUsageSpec);
        return ret;
    }
    ret = HksCryptoHalDecrypt(&dataParams->deriveKekData1, decOriginKeyUsageSpec, kEncData, &originKey);
    HksFreeUsageSpec(&decOriginKeyUsageSpec);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("decrypt importKey failed!");
        HKS_FREE(originKey.data);
        return ret;
    }
    ret = SubPaddingPlaintext(&originKey, &dataParams->originKey, keyMaterialSize);
    ClearAndFreeKeyBlob(&originKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("sub str failed!");
        return ret;
    }
    *partOffset = offset;
    return HKS_SUCCESS;
}

static int32_t HksSmImportWrappedKeyWithVerify(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksKeyNode *keyNode, const struct HksBlob *wrappedKeyData, struct HksBlob *keyOut)
{
    struct HksSmWrappedKeyDataBlob dataParams = { { 0, NULL }, { 0, NULL }, { 0, NULL }, { 0, NULL },
        { 0, NULL }, { 0, NULL }, { 0, NULL }, 0 };
    struct HksBlob kEncData = { 0, NULL };
    uint32_t partOffset = 0;
    int32_t ret = HKS_SUCCESS;
    do {
        /* 1. get peer public key and sign data length, then transfer public key to inner format */
        ret = GetPublicKeyAndSignDataLength(wrappedKeyData, keyNode, &dataParams, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get public key and sign data failed!")

        /*2. decrypt kek data*/
        ret = DecryptKekWithSm2(wrappedKeyData, paramSet, keyNode, &dataParams, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt kek failed!")

        ret = SplitKekAndSignData(&dataParams);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "split kek and sign data failed!")

        /*3. verify data*/
        ret = VerifyKekBySm2(&dataParams);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "verify data failed!")

        /*4. derive kek1 and kek2*/
        ret = DeriveKeyByFactor(wrappedKeyData, &dataParams, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive data failed!")

        /*5. compare hmac*/
        ret = CompareWrapKeyHmac(wrappedKeyData, &dataParams, &kEncData, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "compare kek enc mac failed!")

        /*6. decrypt origin key*/
        ret = DecryptImportedSmKey(wrappedKeyData, &dataParams, &kEncData, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt origin key failed!")

        /* 7. call HksCoreImportKey to build key blob */
        ret = HksCoreImportKey(keyAlias, &dataParams.originKey, paramSet, keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "import origin key failed!")
    } while (0);
    ClearAndFreeWrappedBlob(&dataParams);
    return ret;
}

static int32_t HksSmImportWrappedKeyWithoutVerify(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksKeyNode *keyNode, const struct HksBlob *wrappedKeyData, struct HksBlob *keyOut)
{
    struct HksSmWrappedKeyDataBlob dataParams = { { 0, NULL }, { 0, NULL }, { 0, NULL }, { 0, NULL },
        { 0, NULL }, { 0, NULL }, { 0, NULL }, 0 };
    struct HksBlob kEncData = { 0, NULL };
    uint32_t partOffset = 0;
    int32_t ret = HKS_SUCCESS;

    do {
        /* 1. decrypt kek data*/
        ret = DecryptKekWithSm2(wrappedKeyData, paramSet, keyNode, &dataParams, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt kek failed!")

        /* 2. derive kek1 and kek2*/
        ret = DeriveKeyByFactor(wrappedKeyData, &dataParams, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive data failed!")

        /* 3. compare hmac*/
        ret = CompareWrapKeyHmac(wrappedKeyData, &dataParams, &kEncData, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "compare kek enc mac failed!")

        /* 4. decrypt origin key*/
        ret = DecryptImportedSmKey(wrappedKeyData, &dataParams, &kEncData, &partOffset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt origin key failed!")

        /* 5. call HksCoreImportKey to build key blob */
        ret = HksCoreImportKey(keyAlias, &dataParams.originKey, paramSet, keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "import origin key failed!")
    } while (0);
    ClearAndFreeWrappedBlob(&dataParams);
    return ret;
}

static int32_t CheckAlgAndGetSuit(const struct HksParamSet *paramSet, uint32_t *suit)
{
    struct HksParam *alg = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &alg);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL,
        "get param %" LOG_PUBLIC "u failed!", HKS_TAG_ALGORITHM)
    ret = HksCheckValue(alg->uint32Param, g_validCipher, HKS_ARRAY_SIZE(g_validCipher));
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_AUTH_TYPE)

    struct HksParam *algorithmSuite = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_UNWRAP_ALGORITHM_SUITE, &algorithmSuite);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL, "get unwrap algorithm suite fail");
    *suit = algorithmSuite->uint32Param;
    return HKS_SUCCESS;
}

int32_t HksSmImportWrappedKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappingKey, const struct HksBlob *wrappedKeyData, struct HksBlob *keyOut)
{
    if ((CheckBlob(wrappingKey) != HKS_SUCCESS) || (CheckBlob(wrappedKeyData) != HKS_SUCCESS)) {
        HKS_LOG_E("invalid argument!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    uint32_t algSuit = 0;
    int32_t ret = CheckAlgAndGetSuit(paramSet, &algSuit);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "check failed.");

    struct HksKeyNode *wrappingKeyNode = HksGenerateKeyNode(wrappingKey);
    HKS_IF_NULL_LOGE_RETURN(wrappingKeyNode, HKS_ERROR_CORRUPT_FILE, "generate keynode failed")

    if (algSuit == HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7_WITH_VERIFY_DIG_SM3) {
        ret = HksSmImportWrappedKeyWithVerify(keyAlias, paramSet, wrappingKeyNode, wrappedKeyData, keyOut);
    } else if (algSuit == HKS_UNWRAP_SUITE_SM2_SM4_128_CBC_PKCS7) {
        ret = HksSmImportWrappedKeyWithoutVerify(keyAlias, paramSet, wrappingKeyNode, wrappedKeyData, keyOut);
    } else {
        HKS_LOG_E("invalid alg suit!");
        ret = HKS_ERROR_NOT_SUPPORTED;
    }
    HksFreeKeyNode(&wrappingKeyNode);
    return ret;
}

static int32_t HksGetSm2RawKeyAndParm(const struct HksBlob *wrappingKey, struct HksParamSet **decryptParamSet,
    struct HksBlob *rawKey)
{
    int32_t ret = HKS_SUCCESS;
    struct HksKeyNode *wrappingKeyNode = HksGenerateKeyNode(wrappingKey);
    HKS_IF_NULL_LOGE_RETURN(wrappingKeyNode, HKS_ERROR_CORRUPT_FILE, "envelop generate keynode failed")
    do {
        ret = GetSm2DecryptParamSet(wrappingKeyNode->paramSet, decryptParamSet);
        HKS_IF_NOT_SUCC_BREAK(ret, "get envelop decrypt param failed!")

        ret = HksGetRawKey(wrappingKeyNode->paramSet, rawKey);
        HKS_IF_NOT_SUCC_BREAK(ret, "cipher get envelop raw key failed!")
    } while (0);
    HksFreeKeyNode(&wrappingKeyNode);
    return ret;
}

static int32_t GetKeySize(const struct HksParamSet *paramSet, uint32_t *size)
{
    int32_t ret = HKS_ERROR_PARAM_NOT_EXIST;
    struct HksParam *keySize = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_SIZE, &keySize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Envelop Get Key Size Fail!")
    *size = HKS_KEY_BYTES(keySize->uint32Param);
    return ret;
}

static int32_t HksGetCipherFromEnvelop(const struct HksBlob *wrappingKey, const struct HksBlob *wrappedKeyData,
    const struct HksParamSet *paramSet, struct HksBlob *plianCipher)
{
    struct HksUsageSpec CipherSM4Usage = { .algType = HKS_ALG_SM4, .mode = HKS_MODE_ECB, .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE, .purpose = HKS_KEY_PURPOSE_DECRYPT, .algParam = NULL};
    uint32_t blobIndex = 0;
    struct HksBlob encKekData = {0, NULL};
    int32_t ret = HksGetBlobFromWrappedData(wrappedKeyData, blobIndex++, HKS_IMPORT_ENVELOP_TOTAL_BLOBS, &encKekData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Envelop Get enc-sm4Key Fail!")

    uint32_t importKeySize = 0;
    ret = GetKeySize(paramSet, &importKeySize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL, "Envelop Get Key Size Fail!!")

    struct HksBlob plainImportKey = {0, NULL};
    struct HksBlob encImportKey = {0, NULL};
    ret = HksGetBlobFromWrappedData(wrappedKeyData, blobIndex++, HKS_IMPORT_ENVELOP_TOTAL_BLOBS, &encImportKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Envelop Get enc-importKey Fail!")
    if (importKeySize != encImportKey.size) {
        HKS_LOG_E("Envelop param: %"LOG_PUBLIC"u, wrapped size:%"LOG_PUBLIC"u", importKeySize, encImportKey.size);
        return HKS_ERROR_INVALID_KEY_SIZE;
    }
    struct HksParamSet *decryptParamSet = NULL;
    struct HksBlob rawKey = {0, NULL};
    struct HksUsageSpec *cipherSM2Usage = NULL;
    uint32_t plainKekSize = HKS_KEY_BYTES(HKS_SM2_KEY_SIZE_256);
    struct HksBlob plainKek = {0, NULL};
    do {
        ret = HKS_ERROR_MALLOC_FAIL;
        plainKek.size = plainKekSize,
        plainKek.data = (uint8_t *)HksMalloc(plainKekSize);
        HKS_IF_NULL_LOGE_BREAK(plainKek.data, "Envelop Malloc Fail!!")

        plainImportKey.size = importKeySize,
        plainImportKey.data = (uint8_t *)HksMalloc(importKeySize);
        HKS_IF_NULL_LOGE_BREAK(plainImportKey.data, "Envelop Malloc Fail!!")
        ret = HksGetSm2RawKeyAndParm(wrappingKey, &decryptParamSet, &rawKey);
        HKS_IF_NOT_SUCC_BREAK(ret, "get envelp raw key faill!!")
        ret = HksBuildCipherUsageSpec(decryptParamSet, false, &encKekData, &cipherSM2Usage);
        HKS_IF_NOT_SUCC_BREAK(ret, "envelop build usage failed!")
        ret = HksOpensslSm2Decrypt(&rawKey, cipherSM2Usage, &encKekData, &plainKek);
        HKS_IF_NOT_SUCC_BREAK(ret, "envelop decrypt kek failed")
        ret = HksOpensslSm4Decrypt(&plainKek, &CipherSM4Usage, &encImportKey, &plainImportKey);
        HKS_IF_NOT_SUCC_BREAK(ret, "envelop derive data failed!")
    } while (0);
    plianCipher->size = plainImportKey.size;
    plianCipher->data = plainImportKey.data;
    HKS_MEMSET_FREE_BLOB(rawKey);
    HKS_MEMSET_FREE_BLOB(plainKek);
    HksFreeParamSet(&decryptParamSet);
    HksFreeUsageSpec(&cipherSM2Usage);

    return ret;
}

static int32_t HksBuildDhMaterial(const struct HksParam *pkData, struct HksBlob *privateKey, struct HksBlob *importKey)
{
    HKS_IF_TRUE_LOGE_RETURN(pkData->blob.size < sizeof(struct HksKeyMaterialDh), HKS_ERROR_INVALID_ARGUMENT,
        "invalid public key size");

    struct HksKeyMaterialDh dhData = *(struct HksKeyMaterialDh *)pkData->blob.data;
    HKS_IF_TRUE_LOGE_RETURN(pkData->blob.size != sizeof(struct HksKeyMaterialDh) + dhData.pubKeySize,
        HKS_ERROR_INVALID_ARGUMENT, "invalid public key struct");

    dhData.priKeySize = privateKey->size;
    uint32_t totalSize = dhData.priKeySize + dhData.pubKeySize + sizeof(struct HksKeyMaterialDh);

    importKey->size = totalSize;
    importKey->data = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(importKey->data, HKS_ERROR_MALLOC_FAIL, "Envelop Malloc Fail!!")

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data, totalSize, &dhData, sizeof(struct HksKeyMaterialDh)) != EOK,
        HKS_ERROR_ENVELOP_BUILD_DH_22519_MATERIAL_FAIL, "Envelop Memcpy DH/25519 Material Fail!");
    uint32_t pos = sizeof(struct HksKeyMaterialDh);
    totalSize -= sizeof(struct HksKeyMaterialDh);

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data + pos, totalSize, pkData->blob.data +
        sizeof(struct HksKeyMaterialDh), pkData->blob.size - sizeof(struct HksKeyMaterialDh)) != EOK,
        HKS_ERROR_ENVELOP_BUILD_DH_22519_MATERIAL_FAIL, "Envelop Memcpy DH/25519 PubKey Fail!");
    pos += pkData->blob.size - sizeof(struct HksKeyMaterialDh);
    totalSize -= pkData->blob.size - sizeof(struct HksKeyMaterialDh);

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data + pos, totalSize, privateKey->data, privateKey->size) != EOK,
        HKS_ERROR_ENVELOP_BUILD_DH_22519_MATERIAL_FAIL, "Envelop Memcpy DH/25519 ribKey Fail!");

    return HKS_SUCCESS;
}
static int32_t HksBuildRsaMaterial(const struct HksParam *pkData, struct HksBlob *privateKey,
    struct HksBlob *importKey)
{
    HKS_IF_TRUE_LOGE_RETURN(pkData->blob.size < sizeof(struct HksKeyMaterialRsa), HKS_ERROR_INVALID_ARGUMENT,
        "invalid public key size");

    struct HksKeyMaterialRsa rsaData = *(struct HksKeyMaterialRsa *)pkData->blob.data;
    HKS_IF_TRUE_LOGE_RETURN(pkData->blob.size != sizeof(struct HksKeyMaterialRsa) + rsaData.eSize + rsaData.nSize,
        HKS_ERROR_INVALID_ARGUMENT, "invalid public key struct");

    rsaData.dSize = privateKey->size;
    uint32_t totalSize = rsaData.dSize + rsaData.eSize + rsaData.nSize + sizeof(struct HksKeyMaterialRsa);

    importKey->size = totalSize;
    importKey->data = (uint8_t *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(importKey->data, HKS_ERROR_MALLOC_FAIL, "Envelop Malloc Fail!!")

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data, totalSize, &rsaData, sizeof(struct HksKeyMaterialRsa)) != EOK,
        HKS_ERROR_ENVELOP_BUILD_RSA_ECC_SM2_MATERIAL_FAIL, "Envelop Memcpy RSA/ECC/SM2 Material Fail!");
    uint32_t pos = sizeof(struct HksKeyMaterialRsa);
    totalSize -= sizeof(struct HksKeyMaterialRsa);

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data + pos, totalSize, pkData->blob.data +
        sizeof(struct HksKeyMaterialRsa), pkData->blob.size - sizeof(struct HksKeyMaterialRsa)) != EOK,
        HKS_ERROR_ENVELOP_BUILD_RSA_ECC_SM2_MATERIAL_FAIL, "Envelop Memcpy RSA/ECC/SM2 PubKey Fail!");
    pos += pkData->blob.size - sizeof(struct HksKeyMaterialRsa);
    totalSize -= pkData->blob.size - sizeof(struct HksKeyMaterialRsa);

    HKS_IF_TRUE_LOGE_RETURN(memcpy_s(importKey->data + pos, totalSize, privateKey->data, privateKey->size) != EOK,
        HKS_ERROR_ENVELOP_BUILD_RSA_ECC_SM2_MATERIAL_FAIL, "Envelop Memcpy RSA/ECC/SM2 ribKey Fail!");
    return HKS_SUCCESS;
}

static int32_t HksEnvelopBuildCipherMaterial(uint32_t algTag, const struct HksParamSet *paramSet,
    struct HksBlob *privateKey, struct HksBlob *importKey)
{
    struct HksParam *pkData = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA, &pkData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Envelop Get EnpriKey Fail!!")
    ret = HKS_SUCCESS;
    switch (algTag) {
        case HKS_ALG_ECC:
        case HKS_ALG_RSA:
        case HKS_ALG_SM2:
            ret = HksBuildRsaMaterial(pkData, privateKey, importKey);
            break;
        case HKS_ALG_DH:
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            ret = HksBuildDhMaterial(pkData, privateKey, importKey);
            break;
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return ret;
}

int32_t HksEnvelopBuildKeyMaterial(uint32_t alg, const struct HksParamSet *paramSet,
    struct HksBlob *plainPrivatCipher, struct HksBlob *plainImportKey)
{
    int32_t ret = HKS_SUCCESS;
    switch (alg) {
        case HKS_ALG_RSA:
        case HKS_ALG_ECC:
        case HKS_ALG_SM2:
        case HKS_ALG_DH:
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            ret = HksEnvelopBuildCipherMaterial(alg, paramSet, plainPrivatCipher, plainImportKey);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Envelop Buil Cipher Material Fail!")
            break;
        case HKS_ALG_DSA:
            HKS_LOG_E("DSA Not Support!");
            return HKS_ERROR_NOT_SUPPORTED;
        default:
            *plainImportKey = *plainPrivatCipher;
            plainPrivatCipher->size = 0;
            plainPrivatCipher->data = NULL;
            break;
        }
        return ret;
}

int32_t HksEnvelopImportWrapedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKey,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    int32_t ret = HKS_SUCCESS;
    if ((CheckBlob(wrappingKey) != HKS_SUCCESS) || (CheckBlob(wrappedKeyData) != HKS_SUCCESS)) {
        HKS_LOG_E("invalid argument!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob plainImportKey = {0, NULL};
    struct HksBlob plainPrivatCipher = {0, NULL};
    struct HksParam *importAlg = NULL;
    do {
        ret = HksGetCipherFromEnvelop(wrappingKey, wrappedKeyData, paramSet, &plainPrivatCipher);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get Enveloped Cipher Fail!!")
        ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &importAlg);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get Envelop ALg Fail!!")
        HksEnvelopBuildKeyMaterial(importAlg->uint32Param, paramSet, &plainPrivatCipher, &plainImportKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Build Key Material Fail!!")
        ret = HksCoreImportKey(keyAlias, &plainImportKey, paramSet, keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "envelop import data failed!")
    } while (0);
    HKS_MEMSET_FREE_BLOB(plainImportKey);
    HKS_MEMSET_FREE_BLOB(plainPrivatCipher);

    return ret;
}
#else

int32_t HksEnvelopImportWrapedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKey,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    (void)keyAlias;
    (void)paramSet;
    (void)wrappingKey;
    (void)wrappedKeyData;
    (void)keyOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

int32_t HksSmImportWrappedKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappingKey, const struct HksBlob *wrappedKeyData, struct HksBlob *keyOut)
{
    (void)keyAlias;
    (void)paramSet;
    (void)wrappingKey;
    (void)wrappedKeyData;
    (void)keyOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
}
#endif