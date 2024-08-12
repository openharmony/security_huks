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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_service_key_operate_one_stage.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_auth.h"
#include "hks_base_check.h"
#include "hks_check_paramset.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_core_service_three_stage.h"
#include "hks_crypto_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_secure_access.h"
#include "hks_template.h"

#ifdef HKS_ENABLE_UPGRADE_KEY
#include "hks_upgrade_key.h"
#endif

#include "securec.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

static int32_t CipherAuth(const struct HksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append cipher get alg param failed!")

    if ((algParam->uint32Param == HKS_ALG_AES) || (algParam->uint32Param == HKS_ALG_SM4)) {
        return HksAuth(HKS_AUTH_ID_SYM_CIPHER, keyNode, paramSet);
    } else if ((algParam->uint32Param == HKS_ALG_RSA) || (algParam->uint32Param == HKS_ALG_SM2)) {
        return HksAuth(HKS_AUTH_ID_ASYM_CIPHER, keyNode, paramSet);
    } else {
        return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t SignVerifyAuth(const struct HksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append cipher get alg param failed!")

    if (algParam->uint32Param == HKS_ALG_RSA) {
        struct HksParam *padding = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_PADDING, &padding);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append sign/verify get padding param failed!")
        if (padding->uint32Param == HKS_PADDING_PSS) {
            ret = HksCheckKeyBlobParamSetEqualRuntimeParamSet(keyNode->paramSet,
                paramSet, HKS_TAG_RSA_PSS_SALT_LEN_TYPE);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckKeyBlobParamSetEqualRuntimeParamSet failed!")
        }
        return HksAuth(HKS_AUTH_ID_SIGN_VERIFY_RSA, keyNode, paramSet);
    } else if (algParam->uint32Param == HKS_ALG_ECC) {
        return HksAuth(HKS_AUTH_ID_SIGN_VERIFY_ECC, keyNode, paramSet);
    } else if (algParam->uint32Param == HKS_ALG_DSA) {
        return HKS_SUCCESS;
    } else if (algParam->uint32Param == HKS_ALG_ED25519) {
        return HksAuth(HKS_AUTH_ID_SIGN_VERIFY_ED25519, keyNode, paramSet);
    } else {
        return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t GetSignVerifyMessage(const struct HksParamSet *nodeParamSet, const struct HksBlob *srcData,
    struct HksBlob *message, bool *needFree, const struct HksParamSet *paramSet)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(nodeParamSet, HKS_TAG_ALGORITHM, &algParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_ALG_FAIL, "get param get 0x%" LOG_PUBLIC "x failed",
        HKS_TAG_ALGORITHM)
    struct HksParam *digestParam = NULL;
    ret = HksGetParam(nodeParamSet, HKS_TAG_DIGEST, &digestParam);
    if (ret == HKS_ERROR_INVALID_ARGUMENT) {
        HKS_LOG_E("SignVerify get digestParam failed!");
        return HKS_ERROR_CHECK_GET_DIGEST_FAIL;
    }
    if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        HKS_LOG_I("nodeParamSet get digest failed, now get digest from paramSet");
        ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_CHECK_GET_DIGEST_FAIL, "SignVerify get digestParam failed!");
    }

    if (HksCheckNeedCache(algParam->uint32Param, digestParam->uint32Param) == HKS_SUCCESS) {
        message->size = srcData->size;
        message->data = srcData->data;
        *needFree = false;
    } else {
        message->size = MAX_HASH_SIZE;
        message->data = (uint8_t *)HksMalloc(MAX_HASH_SIZE);
        if (message->data == NULL) {
            HKS_LOG_E("SignVerify malloc message data failed!");
            return HKS_ERROR_MALLOC_FAIL;
        }

        ret = HksCryptoHalHash(digestParam->uint32Param, srcData, message);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("SignVerify calc hash failed!");
            HKS_FREE(message->data);
            return ret;
        }

        *needFree = true;
    }
    return HKS_SUCCESS;
}

static int32_t SignVerifyPreCheck(const struct HksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    int32_t ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return SignVerifyAuth(keyNode, paramSet);
}

static int32_t SignVerify(uint32_t cmdId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    int32_t ret = HksCoreCheckSignVerifyParams(cmdId, key, paramSet, srcData, signature);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "hks failed to check signature or verify params, cmdId:%" LOG_PUBLIC "x, ret:%" LOG_PUBLIC "x!\n", cmdId, ret)

    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "SignVerify generate keynode failed")

    bool needFree = true;
    struct HksBlob message = { 0, NULL };
    do {
        ret = SignVerifyPreCheck(keyNode, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = GetSignVerifyMessage(keyNode->paramSet, srcData, &message, &needFree, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "SignVerify calc hash failed!")

        struct HksBlob rawKey = { 0, NULL };
        ret = HksGetRawKey(keyNode->paramSet, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "SignVerify get raw key failed!")

        struct HksUsageSpec usageSpec = {0};
        HksFillUsageSpec(paramSet, &usageSpec);
        SetRsaPssSaltLenType(paramSet, &usageSpec);
        HKS_LOG_I("Sign or verify.");
        if (cmdId == HKS_CMD_ID_SIGN) {
            ret = HksCryptoHalSign(&rawKey, &usageSpec, &message, signature);
        } else {
            ret = HksCryptoHalVerify(&rawKey, &usageSpec, &message, signature);
        }
        (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
        HKS_FREE(rawKey.data);
    }while (0);

    HksFreeKeyNode(&keyNode);
    if (needFree) {
        HKS_FREE(message.data);
    }
    return ret;
}

static int32_t CipherPreCheck(const struct HksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    int32_t ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return CipherAuth(keyNode, paramSet);
}

static int32_t CipherEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksUsageSpec *usageSpec, const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob tag = { 0, NULL };
    int32_t ret = HksGetEncryptAeTag(paramSet, inData, outData, &tag);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "cipher encrypt get ae tag failed!")

    ret = HksCryptoHalEncrypt(key, usageSpec, inData, outData, &tag);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "cipher encrypt failed!")

    outData->size += tag.size;
    return HKS_SUCCESS;
}

static int32_t Cipher(uint32_t cmdId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    int32_t ret = HksCoreCheckCipherParams(cmdId, key, paramSet, inData, outData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "hks core check cipher params failed, cmdId:%" LOG_PUBLIC "x, ret:%" LOG_PUBLIC "x!\n", cmdId, ret)

    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "Cipher generate keynode failed")

    do {
        ret = CipherPreCheck(keyNode, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "cipher pre check failed!")

        struct HksBlob rawKey = { 0, NULL };
        ret = HksGetRawKey(keyNode->paramSet, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "cipher get raw key failed!")

        struct HksUsageSpec *usageSpec = NULL;
        bool isEncrypt = (cmdId == HKS_CMD_ID_ENCRYPT);
        struct HksBlob tmpInData = { inData->size, inData->data };
        ret = HksBuildCipherUsageSpec(paramSet, isEncrypt, &tmpInData, &usageSpec);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("build cipher usageSpec failed!");
            (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
            HKS_FREE(rawKey.data);
            break;
        }

        if (cmdId == HKS_CMD_ID_ENCRYPT) {
            ret = CipherEncrypt(&rawKey, paramSet, usageSpec, &tmpInData, outData);
        } else {
            ret = HksCryptoHalDecrypt(&rawKey, usageSpec, &tmpInData, outData);
        }
        (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
        HKS_FREE(rawKey.data);

        HksFreeUsageSpec(&usageSpec);
        HKS_IF_NOT_SUCC_LOGE(ret, "cipher[%" LOG_PUBLIC "x] failed!", cmdId)
    }while (0);

    HksFreeKeyNode(&keyNode);
    return ret;
}

int32_t HksCoreSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    return SignVerify(HKS_CMD_ID_SIGN, key, paramSet, srcData, signature);
}

int32_t HksCoreVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    return SignVerify(HKS_CMD_ID_VERIFY, key, paramSet, srcData, (struct HksBlob *)signature);
}

int32_t HksCoreEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    return Cipher(HKS_CMD_ID_ENCRYPT, key, paramSet, plainText, cipherText);
}

int32_t HksCoreDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    return Cipher(HKS_CMD_ID_DECRYPT, key, paramSet, cipherText, plainText);
}

static int32_t HksCheckKeyValidity(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "check key legality failed")

    int32_t ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);

    HksFreeKeyNode(&keyNode);
    return ret;
}

int32_t HksCoreGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    return HksCheckKeyValidity(paramSet, key);
}

int32_t HksCoreExportPublicKey(const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    (void)paramSet;
    if (CheckBlob(key) != HKS_SUCCESS || CheckBlob(keyOut) != HKS_SUCCESS) {
        HKS_LOG_E("input param invalid");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "SignVerify generate keynode failed")

    int32_t ret;
    do {
        ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        struct HksBlob rawKey = { 0, NULL };
        ret = HksGetRawKey(keyNode->paramSet, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get raw key when exporting public key failed!")

        ret = HksCryptoHalGetPubKey(&rawKey, keyOut);
        (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
        HKS_FREE(rawKey.data);
    } while (0);

    HksFreeKeyNode(&keyNode);
    return ret;
}

int32_t HksCoreAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    int32_t ret = HksCoreCheckAgreeKeyParams(paramSet, privateKey, peerPublicKey, agreedKey, false);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check agreeKey params failed")

    struct HksKeyNode *privateKeyNode = HksGenerateKeyNode(privateKey);
    HKS_IF_NULL_LOGE_RETURN(privateKeyNode, HKS_ERROR_CORRUPT_FILE, "agree key generate keynode failed")

    do {
        ret = HksProcessIdentityVerify(privateKeyNode->paramSet, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        bool isSupportUserAuth = false;
        ret = HksCheckKeybBlobIsSupportUserAuth(privateKeyNode->paramSet, &isSupportUserAuth);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckKeybBlobIsSupportUserAuth failed");

        if (isSupportUserAuth) {
            ret = HKS_ERROR_NOT_SUPPORTED;
            HKS_LOG_E("key should do user auth, but one stage api do not support user auth operation");
            break;
        }

        struct HksBlob key = { 0, NULL };
        ret = HksGetRawKey(privateKeyNode->paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get raw key when agreeing key failed!")

        struct HksKeySpec agreeSpec = { 0 };
        HksFillKeySpec(paramSet, &agreeSpec);

        ret = HksCryptoHalAgreeKey(&key, peerPublicKey, &agreeSpec, agreedKey);
        (void)memset_s(key.data, key.size, 0, key.size);
        HKS_FREE(key.data);
    } while (0);

    HksFreeKeyNode(&privateKeyNode);
    return ret;
}

int32_t HksCoreDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey, struct HksBlob *derivedKey)
{
    int32_t ret = HksCoreCheckDeriveKeyParams(paramSet, mainKey, derivedKey, false);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check deriveKey params failed")

    struct HksKeyNode *keyNode = HksGenerateKeyNode(mainKey);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "SignVerify generate keynode failed")

    do {
        ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksAuth(HKS_AUTH_ID_DERIVE, keyNode, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive auth failed!")

        struct HksBlob key = { 0, NULL };
        ret = HksGetRawKey(keyNode->paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "derive get raw key failed!")

        struct HksKeyDerivationParam derParam = { { 0, NULL }, { 0, NULL }, 0, 0 };
        struct HksKeySpec derivationSpec = { 0, 0, &derParam };
        HksFillKeySpec(paramSet, &derivationSpec);
        HksFillKeyDerivationParam(paramSet, &derParam);

        ret = HksCryptoHalDeriveKey(&key, &derivationSpec, derivedKey);
        (void)memset_s(key.data, key.size, 0, key.size);
        HKS_FREE(key.data);
    } while (0);

    HksFreeKeyNode(&keyNode);
    return ret;
}

int32_t HksCoreMac(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *mac)
{
    int32_t ret = HksCoreCheckMacParams(key, paramSet, srcData, mac, false);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check mac params failed")

    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "mac generate keynode failed")

    do {
        ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksAuth(HKS_AUTH_ID_MAC_HMAC, keyNode, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "mac auth failed!")

        struct HksParam *digestParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestParam);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "mac get HKS_TAG_DIGEST param failed!")

        struct HksBlob rawKey = { 0, NULL };
        ret = HksGetRawKey(keyNode->paramSet, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "mac get raw key failed!")

        ret = HksCryptoHalHmac(&rawKey, digestParam->uint32Param, srcData, mac);
        (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
        HKS_FREE(rawKey.data);
    } while (0);

    HksFreeKeyNode(&keyNode);
    return ret;
}

#ifdef HKS_ENABLE_UPGRADE_KEY
int32_t HksCoreUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    return HksUpgradeKey(oldKey, paramSet, newKey);
}

#else
int32_t HksCoreUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet, struct HksBlob *newKey)
{
    (void)oldKey;
    (void)paramSet;
    (void)newKey;
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif