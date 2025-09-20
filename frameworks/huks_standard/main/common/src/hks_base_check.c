/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "hks_base_check.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_base_check_policy.c"

#include "securec.h"

#ifndef _CUT_AUTHENTICATE_
#ifndef _STORAGE_LITE_
static int32_t CheckAndGetKeySize(const struct HksBlob *key, const uint32_t *expectKeySize,
    uint32_t expectCnt, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)

    ret = HksCheckValue(keySizeParam->uint32Param, expectKeySize, expectCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: key size value %" LOG_PUBLIC "u not expected", keySizeParam->uint32Param)
    *keySize = keySizeParam->uint32Param;
    return ret;
}
#else
static int32_t CheckAndGetKeySize(const struct HksBlob *key, const uint32_t *expectKeySize,
    uint32_t expectCnt, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksStoreKeyInfo)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksStoreKeyInfo *keyInfo = (struct HksStoreKeyInfo *)key->data;
    uint32_t keyLen = keyInfo->keyLen;
    int32_t ret = HksCheckValue(keyLen, expectKeySize, expectCnt);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: keySize value %" LOG_PUBLIC "u not expected", keyLen)
    *keySize = keyLen;
    return ret;
}
#endif

#ifdef HKS_SUPPORT_RSA_C
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
int32_t CheckRsaKeySize(uint32_t keyLen)
{
    if ((keyLen >= HKS_RSA_KEY_SIZE_1024) &&
        (keyLen <= HKS_RSA_KEY_SIZE_2048) &&
        ((keyLen % HKS_RSA_KEY_BLOCK_SIZE) == 0)) {
        return HKS_SUCCESS;
    } else {
        return HKS_ERROR_INVALID_KEY_FILE;
    }
}

static int32_t CheckAndGetRsaKeySize(const struct HksBlob *key, uint32_t *keySize)
{
    if (key->size < sizeof(struct HksParamSet)) {
        HKS_LOG_E("check key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)
    ret = CheckRsaKeySize(keySizeParam->uint32Param);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check key size: key size value %" LOG_PUBLIC "u not expected", keySizeParam->uint32Param)
    *keySize = keySizeParam->uint32Param;

    return ret;
}
#endif
#endif

static int32_t CheckPurposeUnique(uint32_t inputPurpose)
{
    /* key usage uniqueness */
    uint32_t purposeCipher = inputPurpose & (HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT);
    uint32_t purposeSign = inputPurpose & (HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY);
    uint32_t purposeDerive = inputPurpose & HKS_KEY_PURPOSE_DERIVE;
    uint32_t purposeWrap = inputPurpose & (HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP);
    uint32_t purposeMac = inputPurpose & HKS_KEY_PURPOSE_MAC;
    uint32_t purposeAgree = inputPurpose & HKS_KEY_PURPOSE_AGREE;

    uint32_t purposeCount = (purposeCipher != 0) ? 1 : 0;
    purposeCount += (purposeSign != 0) ? 1 : 0;
    purposeCount += (purposeDerive != 0) ? 1 : 0;
    purposeCount += (purposeWrap != 0) ? 1 : 0;
    purposeCount += (purposeMac != 0) ? 1 : 0;
    purposeCount += (purposeAgree != 0) ? 1 : 0;

    return (purposeCount == 1) ? HKS_SUCCESS : HKS_ERROR_INVALID_PURPOSE;
}

static int32_t GetInvalidPurpose(uint32_t alg, uint32_t *inputPurpose, uint32_t keyFlag)
{
    int32_t result = HKS_ERROR_INVALID_ALGORITHM;
    if (sizeof(g_invalidPurpose) == 0) {
        return result;
    }
    uint32_t count = sizeof(g_invalidPurpose) / sizeof(g_invalidPurpose[0]);
    for (uint32_t i = 0; i < count; i++) {
        if (alg == g_invalidPurpose[i][0]) {
            result = HKS_SUCCESS;
            *inputPurpose = g_invalidPurpose[i][1];
            break;
        }
    }
    if ((keyFlag != HKS_KEY_FLAG_IMPORT_KEY) || (sizeof(g_invalidImportKeyPurpose) == 0)) {
        return result;
    }
    // add invalid purpose for import key additionally
    count = sizeof(g_invalidImportKeyPurpose) / sizeof(g_invalidImportKeyPurpose[0]);
    for (uint32_t i = 0; i < count; i++) {
        if (alg == g_invalidImportKeyPurpose[i][0]) {
            *inputPurpose |= g_invalidImportKeyPurpose[i][1];
            break;
        }
    }
    return result;
}

static int32_t CheckPurposeValid(uint32_t alg, uint32_t inputPurpose, uint32_t keyFlag)
{
    uint32_t invalidPurpose = 0;

    int32_t result = GetInvalidPurpose(alg, &invalidPurpose, keyFlag);
    HKS_IF_NOT_SUCC_RETURN(result, result)

    if ((inputPurpose & invalidPurpose) != 0) {
        return HKS_ERROR_INVALID_PURPOSE;
    }

    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */

// If tag is optional param, when tag is empty, it is supported.
static int32_t GetOptionalParams(const struct HksParamSet *paramSet, uint32_t tag, bool needCheck, uint32_t* value,
    bool* isAbsent)
{
    if (needCheck) {
        struct HksParam *param;
        int32_t ret = HksGetParam(paramSet, tag, &param);
        if (ret == HKS_SUCCESS) {
            *value = param->uint32Param;
            return ret;
        }
        if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
            HKS_LOG_D("tag [%" LOG_PUBLIC "u] is empty, but it is supported!", tag);
            *isAbsent = true;
            return HKS_SUCCESS;
        }
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t GetInputParams(const struct HksParamSet *paramSet, struct ParamsValues *inputParams)
{
    int32_t ret = HKS_SUCCESS;
    struct HksParam *checkParam = NULL;
    if (inputParams->keyLen.needCheck) {
        ret = HksGetParam(paramSet, HKS_TAG_KEY_SIZE, &checkParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_KEY_SIZE_FAIL,
            "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE);
        inputParams->keyLen.value = checkParam->uint32Param;
    }

    if (inputParams->purpose.needCheck) {
        ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &checkParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_PURPOSE_FAIL,
            "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_PURPOSE);
        inputParams->purpose.value = checkParam->uint32Param;
    }

    ret = GetOptionalParams(paramSet, HKS_TAG_PADDING, inputParams->padding.needCheck, &inputParams->padding.value,
        &inputParams->padding.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_PADDING_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_PADDING);
    ret = GetOptionalParams(paramSet, HKS_TAG_DIGEST, inputParams->digest.needCheck, &inputParams->digest.value,
        &inputParams->digest.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_DIGEST_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_DIGEST);
    ret = GetOptionalParams(paramSet, HKS_TAG_BLOCK_MODE, inputParams->mode.needCheck, &inputParams->mode.value,
        &inputParams->mode.isAbsent);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_MODE_FAIL,
        "get Param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_BLOCK_MODE);
    return ret;
}

static int32_t InitInputParams(enum CheckKeyType checkType, struct ParamsValues *inputParams,
    const struct ParamsValuesChecker *checkSet, uint32_t checkSetSize)
{
    for (uint32_t i = 0; i < checkSetSize; ++i) {
        if (checkType == checkSet[i].checkType) {
            (void)memcpy_s(inputParams, sizeof(*inputParams), &checkSet[i].paramValues,
                sizeof(checkSet[i].paramValues));
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}

int32_t InitInputParamsByAlg(uint32_t alg, enum CheckKeyType checkType, struct ParamsValues *inputParams)
{
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_hksAlgParamSetHandlerPart1); i++) {
        if (alg == g_hksAlgParamSetHandlerPart1[i].alg) {
            return InitInputParams(checkType, inputParams, g_hksAlgParamSetHandlerPart1[i].algParamSet,
                g_hksAlgParamSetHandlerPart1[i].algParamSetCnt);
        }
    }

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_hksAlgParamSetHandlerPart2); i++) {
        if (alg == g_hksAlgParamSetHandlerPart2[i].alg) {
            return InitInputParams(checkType, inputParams, g_hksAlgParamSetHandlerPart2[i].algParamSet,
                g_hksAlgParamSetHandlerPart2[i].algParamSetCnt);
        }
    }

    HKS_LOG_E("init input params by alg fail, alg: %" LOG_PUBLIC "u, checkType: %" LOG_PUBLIC "u", alg, checkType);
    return HKS_ERROR_INVALID_ALGORITHM;
}

static int32_t InitExpectParams(enum CheckKeyType checkType, struct ExpectParamsValues *expectValues,
    const struct ExpectParamsValuesChecker *checkSet, uint32_t checkSetSize)
{
    for (uint32_t i = 0; i < checkSetSize; ++i) {
        if (checkType == checkSet[i].checkType) {
            (void)memcpy_s(expectValues, sizeof(*expectValues), &checkSet[i].paramValues,
                sizeof(checkSet[i].paramValues));
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}

int32_t GetExpectParams(uint32_t alg, enum CheckKeyType checkType, struct ExpectParamsValues *expectValues)
{
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_hksAlgParamSetHandlerPart1); i++) {
        if (alg == g_hksAlgParamSetHandlerPart1[i].alg) {
            return InitExpectParams(checkType, expectValues, g_hksAlgParamSetHandlerPart1[i].expectParams,
                g_hksAlgParamSetHandlerPart1[i].expectParamsCnt);
        }
    }

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_hksAlgParamSetHandlerPart2); i++) {
        if (alg == g_hksAlgParamSetHandlerPart2[i].alg) {
            return InitExpectParams(checkType, expectValues, g_hksAlgParamSetHandlerPart2[i].expectParams,
                g_hksAlgParamSetHandlerPart2[i].expectParamsCnt);
        }
    }

    HKS_LOG_E("get expect params fail, alg: %" LOG_PUBLIC "u, checkType: %" LOG_PUBLIC "u", alg, checkType);
    return HKS_ERROR_INVALID_ALGORITHM;
}

#ifdef HKS_SUPPORT_ECC_C
static int32_t CheckEccSignature(uint32_t cmdId, uint32_t keySize, const struct HksBlob *signature)
{
    /*
     * ecc sign format: 0x30 + len1 + 0x02 + len2 + 0x00 (optional) + r + 0x02 + len3 + 0x00(optional) + s
     * sign: signSize no less than 2*keySize/8 + 8;
     * verify: signSize no greater than 2*keySize/8 + 8
     */
    uint32_t eccSignRSize = keySize / HKS_BITS_PER_BYTE + keySize % HKS_BITS_PER_BYTE;
    uint32_t eccSignSSize = eccSignRSize;
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < (eccSignRSize + eccSignSSize + HKS_ECC_SIGN_MAX_TL_SIZE)) {
                HKS_LOG_E("eccsign: signature size too small, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size > (eccSignRSize + eccSignSSize + HKS_ECC_SIGN_MAX_TL_SIZE)) {
                HKS_LOG_E("eccverfiy: invalid signature size, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ED25519_C
static int32_t CheckEd25519Signature(uint32_t cmdId, const struct HksBlob *signature)
{
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
                HKS_LOG_E("ed25519 sign: signature size too small, signatureSize %" LOG_PUBLIC "u", signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size < HKS_SIGNATURE_MIN_SIZE) {
                HKS_LOG_E("ed25519 verfiy: invalid signature size, signatureSize %" LOG_PUBLIC "u", signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_RSA_C
static int32_t CheckRsaGenKeyPadding(const struct ParamsValues *inputParams)
{
    if (inputParams->padding.isAbsent) {
        return HKS_SUCCESS;
    }
    if ((inputParams->purpose.value & (HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT)) != 0) {
        return HksCheckValue(inputParams->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
    } else if ((inputParams->purpose.value & (HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY)) != 0) {
        return HksCheckValue(inputParams->padding.value, g_rsaSignPadding, HKS_ARRAY_SIZE(g_rsaSignPadding));
    }
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_RSA_SIGN_VERIFY
static int32_t CheckRsaSignature(uint32_t cmdId, uint32_t keySize, const struct HksBlob *signature)
{
    /*
     * k: the length of the RSA modulus n
     * sign: signSize no less than k; verify: signSize is same as k, thus no greater than keySize / 8
     */
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if (signature->size < keySize / HKS_BITS_PER_BYTE) {
                HKS_LOG_E("rsasign: signature size too small, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if (signature->size > keySize / HKS_BITS_PER_BYTE) {
                HKS_LOG_E("rsaverfiy: invalid signature size, keySize %" LOG_PUBLIC "u, signatureSize %" LOG_PUBLIC "u",
                    keySize, signature->size);
                return HKS_ERROR_INVALID_SIGNATURE_SIZE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_RSA_CRYPT
static int32_t CheckRsaNoPadCipherData(uint32_t keySize, const struct HksBlob *inData,
    const struct HksBlob *outData)
{
    /* encrypt/decrypt: inSize no greater than keySize, outSize no less than keySize */
    if (inData->size > keySize) {
        HKS_LOG_E("invalid inData size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u", inData->size, keySize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (outData->size < keySize) {
        HKS_LOG_E("outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
            outData->size, keySize);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return HKS_SUCCESS;
}

static int32_t CheckRsaOaepCipherData(uint32_t cmdId, uint32_t keySize, uint32_t digest,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    uint32_t digestLen;
    if (digest == HKS_DIGEST_NONE) {
        digest = HKS_DIGEST_SHA1;
    }
    int32_t ret = HksGetDigestLen(digest, &digestLen);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetDigestLen failed, ret = %" LOG_PUBLIC "x", ret)

    /*
     * encrypt: inSize no greater than keySize - 2*digestLen - 2, outSize no less than keySize (in: plain; out: cipher)
     * decrypt: inSize no greater than keySize, outSize no less than keySize - 2*digestLen - 2 (in: cipher; out: plain)
     */
    if (keySize <= (HKS_RSA_OAEP_DIGEST_NUM * digestLen + HKS_RSA_OAEP_DIGEST_NUM)) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }
    uint32_t size = keySize - HKS_RSA_OAEP_DIGEST_NUM * digestLen - HKS_RSA_OAEP_DIGEST_NUM;
    if (cmdId == HKS_CMD_ID_ENCRYPT) {
        if (inData->size > size) {
            HKS_LOG_E("encrypt, invalid insize: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u, "
                "digestLen: %" LOG_PUBLIC "u", inData->size, keySize, digestLen);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (outData->size < keySize) {
            HKS_LOG_E("encrypt, outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                outData->size, keySize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } else if (cmdId == HKS_CMD_ID_DECRYPT) {
        if (inData->size > keySize) {
            HKS_LOG_E("decrypt, invalid inData size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                inData->size, keySize);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        if (outData->size < size) {
            HKS_LOG_E("decrypt, outData buffer too small size: %" LOG_PUBLIC "u, keySize: %" LOG_PUBLIC "u",
                outData->size, keySize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckRsaCipherData(uint32_t cmdId, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    uint32_t padding = inputParams->padding.value;
    uint32_t keySize = inputParams->keyLen.value / HKS_BITS_PER_BYTE;
    int32_t ret = HKS_SUCCESS;

    if (padding == HKS_PADDING_NONE) {
        ret = CheckRsaNoPadCipherData(keySize, inData, outData);
    } else if (padding == HKS_PADDING_OAEP) {
        ret = CheckRsaOaepCipherData(cmdId, keySize, inputParams->digest.value, inData, outData);
    }

    HKS_IF_NOT_SUCC_LOGE(ret, "Check Rsa CipherData fail, cmdId: %" LOG_PUBLIC "u, padding: %" LOG_PUBLIC
        "u, keyLen: %" LOG_PUBLIC "u", cmdId, padding, keySize)
    HKS_IF_NOT_SUCC_LOGE(ret, "Check Rsa CipherData fail, inData sz: %" LOG_PUBLIC "u, outData sz: %" LOG_PUBLIC "u",
        inData->size, outData->size)

    return ret;
}
#endif
#endif

#if defined(HKS_SUPPORT_AES_C) || defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C) || \
    defined(HKS_SUPPORT_SM4_C)
static int32_t CheckBlockCbcCipherData(uint32_t mode, uint32_t cmdId, uint32_t padding,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    /*
     * encrypt: inSize greater than 0(has been checked), no-padding: inSize need to be integer multiple of 16
     *          outSize no less than inSize + (16 - inSize % 16) (in: plain; out: cipher)
     * decrypt: inSize greater than 0(has been checked) && inSize is integer multiple of 16
     *          outSize no less than inSize (in: cipher; out: plain)
     */
    switch (cmdId) {
        case HKS_CMD_ID_ENCRYPT: {
            uint32_t paddingSize = 0;
            if (padding == HKS_PADDING_NONE) {
                if ((mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) &&
                    inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE != 0) {
                    HKS_LOG_E("encrypt, mode id: %" LOG_PUBLIC "u, no-padding, invalid inSize: %" LOG_PUBLIC "u",
                        mode, inData->size);
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
            } else {
                paddingSize = HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE - inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE;
                if (inData->size > (UINT32_MAX - paddingSize)) {
                    HKS_LOG_E("encrypt, invalid inData size: %" LOG_PUBLIC "u", inData->size);
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
            }
            if (outData->size < (inData->size + paddingSize)) {
                HKS_LOG_E("encrypt, outData buffer too small size: %" LOG_PUBLIC "u, need: %" LOG_PUBLIC "u",
                    outData->size, inData->size + paddingSize);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        }
        case HKS_CMD_ID_DECRYPT:
            if ((mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) && inData->size % HKS_BLOCK_CIPHER_CBC_BLOCK_SIZE != 0) {
                HKS_LOG_E("decrypt, mode id: %" LOG_PUBLIC "u, invalid inData size: %" LOG_PUBLIC "u",
                    mode, inData->size);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            if (outData->size < inData->size) {
                HKS_LOG_E("decrypt, outData buffer too small size: %" LOG_PUBLIC "u, inDataSize: %" LOG_PUBLIC "u",
                    outData->size, inData->size);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t CheckBlockCipherData(uint32_t cmdId, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData, uint32_t alg)
{
    uint32_t mode = inputParams->mode.value;

#if defined(HKS_SUPPORT_AES_C)
    if (alg == HKS_ALG_AES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_CTR || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_DES_C)
    if (alg == HKS_ALG_DES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_3DES_C)
    if (alg == HKS_ALG_3DES) {
        if (mode == HKS_MODE_CBC || mode == HKS_MODE_ECB) {
            uint32_t padding = inputParams->padding.value;
            return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
        }
    }
#endif

#if defined(HKS_SUPPORT_SM4_C)
    if (alg == HKS_ALG_SM4) {
        for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_sm4Mode); i++) {
            if (mode == g_sm4Mode[i]) {
                uint32_t padding = inputParams->padding.value;
                return CheckBlockCbcCipherData(mode, cmdId, padding, inData, outData);
            }
        }
    }
#endif

    return HKS_ERROR_INVALID_MODE;
}

static int32_t CheckBlockCipherIvMaterial(const struct HksParamSet *paramSet)
{
    struct HksParam *ivParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IV, &ivParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_IV_FAIL, "cipher get iv param failed!")

    if ((ivParam->blob.size != HKS_BLOCK_CIPHER_CBC_IV_LEN) || (ivParam->blob.data == NULL)) {
        HKS_LOG_E("cbc iv param invalid");
        return HKS_ERROR_INVALID_IV;
    }

    return ret;
}
#endif // defined(HKS_SUPPORT_AES_C) || defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
       // || defined(HKS_SUPPORT_SM4_C)

#ifdef HKS_SUPPORT_AES_C
static int32_t CheckAesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_aesCbcPadding, HKS_ARRAY_SIZE(g_aesCbcPadding));
    }

    if (mode == HKS_MODE_CTR) {
        return HksCheckValue(padding, g_aesCtrPadding, HKS_ARRAY_SIZE(g_aesCtrPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_aesEcbPadding, HKS_ARRAY_SIZE(g_aesEcbPadding));
    }

    if ((mode == HKS_MODE_GCM) || (mode == HKS_MODE_CCM)) {
        return HksCheckValue(padding, g_aesAeadPadding, HKS_ARRAY_SIZE(g_aesAeadPadding));
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeAadMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    struct HksParam *aadParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ASSOCIATED_DATA, &aadParam);
    if (mode == HKS_MODE_GCM && ret == HKS_ERROR_PARAM_NOT_EXIST) {
        HKS_LOG_W("gcm no input aad");
        return HKS_SUCCESS;
    } else if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher get aad param failed!");
        return HKS_ERROR_CHECK_GET_AAD_FAIL;
    }
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(&aadParam->blob), HKS_ERROR_INVALID_AAD)

    /* gcmMode: aadSize greater than 0 (has been checked); ccmMode: aadSize no less than 4 */
    if (mode == HKS_MODE_CCM) {
        if (aadParam->blob.size < HKS_AES_CCM_AAD_LEN_MIN) {
            HKS_LOG_E("ccm invalid aad size, aad size = %" LOG_PUBLIC "u", aadParam->blob.size);
            return HKS_ERROR_INVALID_AAD;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeNonceMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    struct HksParam *nonceParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_NONCE, &nonceParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_NONCE_FAIL, "cipher get nonce param failed!")
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(&nonceParam->blob), HKS_ERROR_INVALID_NONCE)

    /* gcmMode: nonceSize no less than 12; ccmMode: nonceSize no less than 7, and no greater than 13 */
    if (mode == HKS_MODE_GCM) {
        if (nonceParam->blob.size < HKS_AES_GCM_NONCE_LEN_MIN) {
            HKS_LOG_E("gcm invalid nonce size, nonce size = %" LOG_PUBLIC "u", nonceParam->blob.size);
            return HKS_ERROR_INVALID_NONCE;
        }
    } else if (mode == HKS_MODE_CCM) {
        HKS_IF_TRUE_LOGE_RETURN((nonceParam->blob.size < HKS_AES_CCM_NONCE_LEN_MIN) ||
            (nonceParam->blob.size > HKS_AES_CCM_NONCE_LEN_MAX), HKS_ERROR_INVALID_NONCE,
            "ccm invalid nonce size, nonce size = %" LOG_PUBLIC "u", nonceParam->blob.size);
    }

    return HKS_SUCCESS;
}

static int32_t CheckCipherAeMaterial(uint32_t mode, const struct HksParamSet *paramSet)
{
    int32_t ret = CheckCipherAeAadMaterial(mode, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check ae cipher aad failed!")

    ret = CheckCipherAeNonceMaterial(mode, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check ae cipher nonce failed!")

    return ret;
}
#endif

#ifdef HKS_SUPPORT_DES_C
static int32_t CheckDesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_desCbcPadding, HKS_ARRAY_SIZE(g_desCbcPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_desEcbPadding, HKS_ARRAY_SIZE(g_desEcbPadding));
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_3DES_C
static int32_t Check3DesPadding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_3desCbcPadding, HKS_ARRAY_SIZE(g_3desCbcPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_3desEcbPadding, HKS_ARRAY_SIZE(g_3desEcbPadding));
    }

    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_SM4_C
static int32_t CheckSm4Padding(const struct ParamsValues *inputParams)
{
    if ((inputParams->mode.isAbsent) || (inputParams->padding.isAbsent)) {
        return HKS_SUCCESS;
    }
    uint32_t mode = inputParams->mode.value;
    uint32_t padding = inputParams->padding.value;
    if (mode == HKS_MODE_CBC) {
        return HksCheckValue(padding, g_sm4CbcPadding, HKS_ARRAY_SIZE(g_sm4CbcPadding));
    }

    if (mode == HKS_MODE_CTR) {
        return HksCheckValue(padding, g_sm4CtrPadding, HKS_ARRAY_SIZE(g_sm4CtrPadding));
    }

    if (mode == HKS_MODE_ECB) {
        return HksCheckValue(padding, g_sm4EcbPadding, HKS_ARRAY_SIZE(g_sm4EcbPadding));
    }

    if (mode == HKS_MODE_CFB) {
        return HksCheckValue(padding, g_sm4CfbPadding, HKS_ARRAY_SIZE(g_sm4CfbPadding));
    }

    if (mode == HKS_MODE_OFB) {
        return HksCheckValue(padding, g_sm4OfbPadding, HKS_ARRAY_SIZE(g_sm4OfbPadding));
    }

    return HKS_ERROR_INVALID_ARGUMENT;
}
#endif

int32_t HksCheckValue(uint32_t inputValue, const uint32_t *expectValues, uint32_t valuesCount)
{
    for (uint32_t i = 0; i < valuesCount; ++i) {
        if (inputValue == expectValues[i]) {
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksCheckGenKeyPurpose(uint32_t alg, uint32_t inputPurpose, uint32_t keyFlag)
{
    int32_t ret = CheckPurposeUnique(inputPurpose);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "gen key purpose not unique")

    return CheckPurposeValid(alg, inputPurpose, keyFlag);
}

#ifdef HKS_SUPPORT_DSA_C
static int32_t HksGetDsaKeySize(const struct HksBlob *key, uint32_t *keySize)
{
    HKS_IF_TRUE_LOGE_RETURN(key->size < sizeof(struct HksParamSet), HKS_ERROR_INVALID_KEY_FILE,
        "check dsa key size: invalid keyfile size: %" LOG_PUBLIC "u", key->size);

    struct HksParamSet *keyParamSet = (struct HksParamSet *)key->data;
    int32_t ret = HksCheckParamSetValidity(keyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE, "check dsa key size: paramset invalid failed")

    struct HksParam *keySizeParam = NULL;
    ret = HksGetParam(keyParamSet, HKS_TAG_KEY_SIZE, &keySizeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_KEY_FILE,
        "check dsa key size: get param get tag:0x%" LOG_PUBLIC "x failed", HKS_TAG_KEY_SIZE)
    *keySize = keySizeParam->uint32Param;
    return ret;
}
#endif

int32_t HksGetKeySize(uint32_t alg, const struct HksBlob *key, uint32_t *keySize)
{
    int32_t ret = HKS_ERROR_INVALID_ALGORITHM;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = CheckAndGetKeySize(key, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize), keySize);
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
            if (ret != HKS_SUCCESS) {
                ret = CheckAndGetRsaKeySize(key, keySize);
            }
#endif
            return ret;
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
#ifndef _STORAGE_LITE_
            return HksGetDsaKeySize(key, keySize);
#else
            return HKS_ERROR_INVALID_ALGORITHM;
#endif
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            return CheckAndGetKeySize(key, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize), keySize);
#endif
#ifdef HKS_SUPPORT_ECDH_C
        case HKS_ALG_ECDH:
            return CheckAndGetKeySize(key, g_ecdhKeySize, HKS_ARRAY_SIZE(g_ecdhKeySize), keySize);
#endif
#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
        case HKS_ALG_X25519:
        case HKS_ALG_ED25519:
            return CheckAndGetKeySize(key, g_curve25519KeySize, HKS_ARRAY_SIZE(g_curve25519KeySize), keySize);
#endif
#ifdef HKS_SUPPORT_DH_C
        case HKS_ALG_DH:
            return CheckAndGetKeySize(key, g_dhKeySize, HKS_ARRAY_SIZE(g_dhKeySize), keySize);
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return CheckAndGetKeySize(key, g_sm4KeySize, HKS_ARRAY_SIZE(g_sm4KeySize), keySize);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return CheckAndGetKeySize(key, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize), keySize);
#endif
        default:
            return ret;
    }
}
#endif /* _CUT_AUTHENTICATE_ */

#ifndef _CUT_AUTHENTICATE_
int32_t HksCheckGenKeyMutableParams(uint32_t alg, const struct ParamsValues *inputParams)
{
    int32_t ret = HKS_SUCCESS;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = CheckRsaGenKeyPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            ret = CheckAesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            ret = CheckDesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            ret = Check3DesPadding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            ret = CheckSm4Padding(inputParams);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING,
                "Check padding not expected, padding = %" LOG_PUBLIC "u", inputParams->padding.value);
            break;
#endif
        default:
            /* other alg no need check padding */
            break;
    }

    return ret;
}

int32_t CheckImportMutableParams(uint32_t alg, const struct ParamsValues *params)
{
    if (((alg == HKS_ALG_DSA) || (alg == HKS_ALG_ED25519)) &&
        (params->purpose.value != HKS_KEY_PURPOSE_VERIFY)) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_SM2) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_ENCRYPT))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_ECC) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_UNWRAP) &&
        (params->purpose.value != HKS_KEY_PURPOSE_AGREE))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if ((alg == HKS_ALG_RSA) &&
        ((params->purpose.value != HKS_KEY_PURPOSE_VERIFY) && (params->purpose.value != HKS_KEY_PURPOSE_ENCRYPT))) {
        HKS_LOG_E("Import key check purpose failed.");
        return HKS_ERROR_INVALID_PURPOSE;
    }

    if (alg == HKS_ALG_RSA) {
#ifdef HKS_SUPPORT_RSA_C
        if (params->padding.isAbsent) {
            return HKS_SUCCESS;
        }
        if (params->purpose.value == HKS_KEY_PURPOSE_ENCRYPT) {
            return HksCheckValue(params->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
        } else if (params->purpose.value == HKS_KEY_PURPOSE_VERIFY) {
            return HksCheckValue(params->padding.value, g_rsaSignPadding, HKS_ARRAY_SIZE(g_rsaSignPadding));
        }
#else
        return HKS_ERROR_NOT_SUPPORTED;
#endif
    }

    return HKS_SUCCESS;
}

int32_t HksCheckSignature(uint32_t cmdId, uint32_t alg, uint32_t keySize, const struct HksBlob *signature)
{
    (void)cmdId;
    (void)keySize;
    (void)signature;
    int32_t ret = HKS_ERROR_INVALID_ALGORITHM;
    switch (alg) {
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
        case HKS_ALG_RSA:
            ret = HksCheckValue(keySize, g_rsaKeySize, HKS_ARRAY_SIZE(g_rsaKeySize));
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
            if (ret != HKS_SUCCESS) {
                ret = CheckRsaKeySize(keySize);
            }
#endif
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret,
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckRsaSignature(cmdId, keySize, signature);
#endif
#if defined(HKS_SUPPORT_DSA_C) && defined(HKS_SUPPORT_DSA_SIGN_VERIFY)
        case HKS_ALG_DSA:
            return HKS_SUCCESS;
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckValue(keySize, g_eccKeySize, HKS_ARRAY_SIZE(g_eccKeySize)),
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckEccSignature(cmdId, keySize, signature);
#endif
#ifdef HKS_SUPPORT_ED25519_C
        case HKS_ALG_ED25519:
            return CheckEd25519Signature(cmdId, signature);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckValue(keySize, g_sm2KeySize, HKS_ARRAY_SIZE(g_sm2KeySize)),
                HKS_ERROR_INVALID_ARGUMENT, "check key size: key size value %" LOG_PUBLIC "u not expected", keySize)
            return CheckEccSignature(cmdId, keySize, signature);
#endif
        default:
            return ret;
    }
}

int32_t HksCheckSignVerifyMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams)
{
    switch (cmdId) {
        case HKS_CMD_ID_SIGN:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_SIGN) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        case HKS_CMD_ID_VERIFY:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_VERIFY) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            HKS_IF_NOT_SUCC_RETURN(HksCheckValue(inputParams->padding.value, g_rsaSignPadding,
                HKS_ARRAY_SIZE(g_rsaSignPadding)), HKS_ERROR_INVALID_PADDING)
            break;
#endif
#ifdef HKS_SUPPORT_DSA_C
        case HKS_ALG_DSA:
            break;
#endif
#ifdef HKS_SUPPORT_ECC_C
        case HKS_ALG_ECC:
            break;
#endif
        default:
            /* other alg no need check padding */
            break;
    }
    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */

#if defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
static int32_t HksCheckCipherMutableParamsByAlg(uint32_t alg, const struct ParamsValues *inputParams)
{
    int32_t ret = HKS_ERROR_INVALID_PADDING;
    switch (alg) {
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            ret = CheckDesPadding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            ret = Check3DesPadding(inputParams);
            break;
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }

    return ret;
}
#endif

int32_t HksCheckCipherMutableParams(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams)
{
    switch (cmdId) {
        case HKS_CMD_ID_ENCRYPT:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_ENCRYPT) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        case HKS_CMD_ID_DECRYPT:
            if ((inputParams->purpose.value & HKS_KEY_PURPOSE_DECRYPT) == 0) {
                return HKS_ERROR_INVALID_PURPOSE;
            }
            break;
        default:
            return HKS_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = HKS_ERROR_INVALID_PADDING;
    switch (alg) {
#ifdef HKS_SUPPORT_RSA_C
        case HKS_ALG_RSA:
            ret = HksCheckValue(inputParams->padding.value, g_rsaCipherPadding, HKS_ARRAY_SIZE(g_rsaCipherPadding));
            break;
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            ret = CheckAesPadding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            ret = CheckSm4Padding(inputParams);
            break;
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            ret = HksCheckValue(inputParams->padding.value, g_sm2CipherPadding, HKS_ARRAY_SIZE(g_sm2CipherPadding));
            break;
#endif
        default:
#if defined(HKS_SUPPORT_DES_C) || defined(HKS_SUPPORT_3DES_C)
            ret = HksCheckCipherMutableParamsByAlg(alg, inputParams);
            if (ret == HKS_ERROR_INVALID_ALGORITHM) {
                return HKS_ERROR_INVALID_ALGORITHM;
            }
#endif
            break;
    }
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_PADDING)
    return ret;
}

int32_t HksCheckCipherData(uint32_t cmdId, uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    switch (alg) {
#if defined(HKS_SUPPORT_RSA_C) && defined(HKS_SUPPORT_RSA_CRYPT)
        case HKS_ALG_RSA:
            return CheckRsaCipherData(cmdId, inputParams, inData, outData);
#endif
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_AES);
#endif
#ifdef HKS_SUPPORT_DES_C
        case HKS_ALG_DES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_DES);
#endif
#ifdef HKS_SUPPORT_3DES_C
        case HKS_ALG_3DES:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_3DES);
#endif
#ifdef HKS_SUPPORT_SM4_C
        case HKS_ALG_SM4:
            return CheckBlockCipherData(cmdId, inputParams, inData, outData, HKS_ALG_SM4);
#endif
#ifdef HKS_SUPPORT_SM2_C
        case HKS_ALG_SM2:
            return HKS_SUCCESS;
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

int32_t HksCheckCipherMaterialParams(uint32_t alg, const struct ParamsValues *inputParams,
    const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_AES_C
    if (alg == HKS_ALG_AES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        } else if ((mode == HKS_MODE_CCM) || (mode == HKS_MODE_GCM)) {
            return CheckCipherAeMaterial(mode, paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_DES_C
    if (alg == HKS_ALG_DES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_3DES_C
    if (alg == HKS_ALG_3DES) {
        uint32_t mode = inputParams->mode.value;
        if (mode == HKS_MODE_CBC) {
            return CheckBlockCipherIvMaterial(paramSet);
        }
    }
#endif
#ifdef HKS_SUPPORT_SM4_C
    if (alg == HKS_ALG_SM4) {
        uint32_t mode = inputParams->mode.value;
        HKS_IF_TRUE_RETURN(mode == HKS_MODE_CBC || mode == HKS_MODE_CTR ||
            mode == HKS_MODE_CFB || mode == HKS_MODE_OFB,
            CheckBlockCipherIvMaterial(paramSet));
    }
#endif
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t HasValidAuthAccessType(const struct ExpectParams allowAuthAccessTypes,
    uint32_t authAccessType, uint32_t *matchType)
{
    for (uint32_t i = 0; i < allowAuthAccessTypes.valueCnt; i++) {
        if ((authAccessType & allowAuthAccessTypes.values[i]) != 0) {
            *matchType = allowAuthAccessTypes.values[i];
            return HKS_SUCCESS;
        }
    }
    return HKS_ERROR_INVALID_ARGUMENT;
}

static int32_t CheckTuiPinAccessType(uint32_t authAccessType)
{
    if (authAccessType != HKS_AUTH_ACCESS_ALWAYS_VALID) {
        HKS_LOG_E("invalid authAccessType for TUI PIN, authAccessType = %" LOG_PUBLIC "d", authAccessType);
        return HKS_ERROR_INVALID_ACCESS_TYPE;
    }

    return HKS_SUCCESS;
}

static int32_t HksCheckAuthAccessTypeByUserAuthType(uint32_t userAuthType, uint32_t authAccessType)
{
    if ((userAuthType & HKS_USER_AUTH_TYPE_TUI_PIN) != 0) {
        return CheckTuiPinAccessType(authAccessType);
    }
    uint32_t valuesCnt = HKS_ARRAY_SIZE(g_expectAuthAccessParams);
    uint32_t validAuthAccessType = 0;
    uint32_t tempType = 0;
    for (uint32_t i = 0; i < valuesCnt; i++) {
        struct AuthAccessTypeChecker checker = g_expectAuthAccessParams[i];
        if ((checker.userAuthType & userAuthType) != 0 &&
            HasValidAuthAccessType(checker.allowAuthAccessTypes, authAccessType, &tempType) == HKS_SUCCESS) {
            validAuthAccessType |= tempType;
        }
    }
    if ((authAccessType != 0) && (authAccessType == validAuthAccessType)) {
        HKS_IF_TRUE_LOGE_RETURN((authAccessType & HKS_AUTH_ACCESS_ALWAYS_VALID) != 0 &&
            (authAccessType &(~HKS_AUTH_ACCESS_ALWAYS_VALID)) != 0, HKS_ERROR_INVALID_ACCESS_TYPE,
            "auth access type is invalid: ALWAYS_VALID cannot coexist with other type");
        return HKS_SUCCESS;
    }
    HKS_LOG_E("authAccessType %" LOG_PUBLIC "u is not equal to validAuthAccessType %" LOG_PUBLIC "u or is 0",
        authAccessType, validAuthAccessType);
    return HKS_ERROR_INVALID_ACCESS_TYPE;
}
#endif

int32_t HksCheckUserAuthParams(uint32_t userAuthType, uint32_t authAccessType, uint32_t challengeType)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    int32_t ret = HksCheckValue(userAuthType, g_supportUserAuthTypes, HKS_ARRAY_SIZE(g_supportUserAuthTypes));
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_AUTH_TYPE)

    ret = HksCheckValue(challengeType, g_userAuthChallengeType, HKS_ARRAY_SIZE(g_userAuthChallengeType));
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INVALID_CHALLENGE_TYPE)

    return HksCheckAuthAccessTypeByUserAuthType(userAuthType, authAccessType);
#else
    (void)userAuthType;
    (void)authAccessType;
    (void)challengeType;
    return HKS_SUCCESS;
#endif
}

int32_t HksCheckSecureSignParams(uint32_t secureSignType)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    return HksCheckValue(secureSignType, g_supportSecureSignType, HKS_ARRAY_SIZE(g_supportSecureSignType));
#else
    (void)secureSignType;
    return HKS_SUCCESS;
#endif
}

/* If the algorithm is ed25519, the plaintext is directly cached, and if the digest is HKS_DIGEST_NONE, the
   hash value has been passed in by the user. So the hash value does not need to be free.
*/
int32_t HksCheckNeedCache(uint32_t alg, uint32_t digest)
{
    if ((alg == HKS_ALG_ED25519) || (digest == HKS_DIGEST_NONE)) {
        HKS_LOG_I("need to cache the data");
        return HKS_SUCCESS;
    }
    return HKS_FAILURE;
}

#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
static int32_t CheckUserAuthKeyInfoValidity(const struct HksParamSet *paramSet,
    const struct KeyInfoParams *params, uint32_t paramsCnt)
{
    for (uint32_t i = 0; i < paramsCnt; i++) {
        if (params[i].needCheck) {
            struct HksParam *param = NULL;
            int32_t ret = HksGetParam(paramSet, params[i].tag, &param);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_SUCCESS, "tag is empty and no need to check!")

            ret = HksCheckValue(param->uint32Param, params[i].values, params[i].valueCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "not support tag %" LOG_PUBLIC "u and value is %" LOG_PUBLIC "u",
                params[i].tag, param->uint32Param)
        }
    }
    return HKS_SUCCESS;
}
#endif

int32_t HksCheckUserAuthKeyInfoValidity(const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_USER_AUTH_ACCESS_CONTROL
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckParamSet(paramSet, paramSet->paramSetSize),
    HKS_ERROR_INVALID_ARGUMENT, "invalid paramSet!")

    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get alg param failed!")

    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validKeyInfo); i++) {
        if (algParam->uint32Param == g_validKeyInfo[i].keyAlg) {
            ret = CheckUserAuthKeyInfoValidity(paramSet, g_validKeyInfo[i].params, g_validKeyInfo[i].paramsCnt);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NOT_SUPPORTED, "not support set key auth purpose!")
        }
    }
    HKS_LOG_I("support set key auth purpose!");
    return ret;
#else
    (void)paramSet;
    return HKS_SUCCESS;
#endif
}