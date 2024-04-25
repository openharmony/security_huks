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

#include "hks_api.h"

#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "hks_api_adapter.h"

#include "hks_client_ipc.h"
#include "hks_local_engine.h"
#include "hks_ability.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_util.h"

#include "securec.h"

#ifdef HKS_SUPPORT_API_ATTEST_KEY
#include "hks_verifier.h"
#endif

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_API_GENERATE_KEY
#undef HKS_SUPPORT_API_IMPORT
#undef HKS_SUPPORT_API_EXPORT
#undef HKS_SUPPORT_API_DELETE_KEY
#undef HKS_SUPPORT_API_GET_KEY_PARAM_SET
#undef HKS_SUPPORT_API_KEY_EXIST
#undef HKS_SUPPORT_API_SIGN_VERIFY
#undef HKS_SUPPORT_API_SIGN_VERIFY
#undef HKS_SUPPORT_API_AGREE_KEY
#undef HKS_SUPPORT_API_HASH
#undef HKS_SUPPORT_API_GET_KEY_INFO_LIST
#undef HKS_SUPPORT_API_ATTEST_KEY
#undef HKS_SUPPORT_API_GET_CERTIFICATE_CHAIN
#endif

HKS_API_EXPORT int32_t HksGetSdkVersion(struct HksBlob *sdkVersion)
{
    if ((sdkVersion == NULL) || (sdkVersion->data == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t versionLen = strlen(HKS_SDK_VERSION);
    if (sdkVersion->size < (versionLen + 1)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    (void)memcpy_s(sdkVersion->data, sdkVersion->size, HKS_SDK_VERSION, versionLen);

    sdkVersion->data[versionLen] = '\0';
    sdkVersion->size = versionLen;
    return HKS_SUCCESS;
}

HKS_API_EXPORT int32_t HksInitialize(void)
{
#ifndef _CUT_AUTHENTICATE_
    HKS_LOG_D("enter initialize");
    int32_t ret = HksClientInitialize();
    HKS_LOG_D("leave initialize, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)HksCryptoAbilityInit();
    return HKS_SUCCESS;
#endif
}

HKS_API_EXPORT int32_t HksRefreshKeyInfo(void)
{
#ifndef _CUT_AUTHENTICATE_
    HKS_LOG_D("enter refresh key info");
    int32_t ret = HksClientRefreshKeyInfo();
    HKS_LOG_D("leave refresh key info, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
#ifdef HKS_SUPPORT_API_GENERATE_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    struct HksParam *storageFlag = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_STORAGE_FLAG, &storageFlag);
    if ((ret == HKS_SUCCESS) && (storageFlag->uint32Param == HKS_STORAGE_TEMP)) {
        if ((paramSetIn == NULL) || (paramSetOut == NULL)) {
            return HKS_ERROR_NULL_POINTER;
        }
        ret = HksLocalGenerateKey(paramSetIn, paramSetOut);
        HKS_LOG_D("leave generate temp key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }

    /* generate persistent keys */
    if ((paramSetIn == NULL) || (keyAlias == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    ret = HksClientGenerateKey(keyAlias, paramSetIn, paramSetOut);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSetIn;
    (void)paramSetOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksImportKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key)
{
#ifdef HKS_SUPPORT_API_IMPORT
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (paramSet == NULL) || (key == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksImportKeyAdapter(keyAlias, paramSet, key);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)key;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
#ifdef HKS_SUPPORT_API_IMPORT_WRAPPED_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (wrappingKeyAlias == NULL)|| (paramSet == NULL) || (wrappedKeyData == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientImportWrappedKey(keyAlias, wrappingKeyAlias, paramSet, wrappedKeyData);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)wrappingKeyAlias;
    (void)paramSet;
    (void)wrappedKeyData;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksExportPublicKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
#ifdef HKS_SUPPORT_API_EXPORT
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (key == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksExportPublicKeyAdapter(keyAlias, paramSet, key);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)key;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_API_DELETE_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    HKS_IF_NULL_RETURN(keyAlias, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientDeleteKey(keyAlias, paramSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetKeyParamSet(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
#ifdef HKS_SUPPORT_API_GET_KEY_PARAM_SET
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (paramSetOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetKeyParamSet(keyAlias, paramSetIn, paramSetOut);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSetIn;
    (void)paramSetOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_API_KEY_EXIST
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    HKS_IF_NULL_RETURN(keyAlias, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientKeyExist(keyAlias, paramSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
#ifdef HKS_SUPPORT_API_GENERATE_RANDOM
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    HKS_IF_NULL_RETURN(random, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientGenerateRandom(random, paramSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)paramSet;
    (void)random;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
#ifdef HKS_SUPPORT_API_SIGN_VERIFY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (signature == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        return HksLocalSign(key, paramSet, srcData, signature);
    }

    ret = HksClientSign(key, paramSet, srcData, signature);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)signature;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
#ifdef HKS_SUPPORT_API_SIGN_VERIFY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (signature == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalVerify(key, paramSet, srcData, signature);
        HKS_LOG_D("leave verify with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
    ret = HksClientVerify(key, paramSet, srcData, signature);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)signature;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
#ifdef HKS_SUPPORT_API_CIPHER
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((key == NULL) || (paramSet == NULL) || (plainText == NULL) || (cipherText == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalEncrypt(key, paramSet, plainText, cipherText);
        HKS_LOG_D("leave encrypt with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientEncrypt(key, paramSet, plainText, cipherText);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    return HKS_ERROR_NOT_SUPPORTED;
#endif
#else
    (void)key;
    (void)paramSet;
    (void)plainText;
    (void)cipherText;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
#ifdef HKS_SUPPORT_API_CIPHER
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((key == NULL) || (paramSet == NULL) || (cipherText == NULL) || (plainText == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalDecrypt(key, paramSet, cipherText, plainText);
        HKS_LOG_D("leave decrypt with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientDecrypt(key, paramSet, cipherText, plainText);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    return HKS_ERROR_NOT_SUPPORTED;
#endif
#else
    (void)key;
    (void)paramSet;
    (void)plainText;
    (void)cipherText;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
#ifdef HKS_SUPPORT_API_AGREE_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((paramSet == NULL) || (privateKey == NULL) || (peerPublicKey == NULL) || (agreedKey == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalAgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
        HKS_LOG_D("leave agree key with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }

    ret = HksAgreeKeyAdapter(paramSet, privateKey, peerPublicKey, agreedKey);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)paramSet;
    (void)privateKey;
    (void)peerPublicKey;
    (void)agreedKey;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey)
{
#ifdef HKS_SUPPORT_API_DERIVE_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((paramSet == NULL) || (mainKey == NULL) || (derivedKey == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalDeriveKey(paramSet, mainKey, derivedKey);
        HKS_LOG_D("leave derive key with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientDeriveKey(paramSet, mainKey, derivedKey);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    return HKS_ERROR_NOT_SUPPORTED;
#endif
#else
    (void)paramSet;
    (void)mainKey;
    (void)derivedKey;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
#ifdef HKS_SUPPORT_API_MAC
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (mac == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalMac(key, paramSet, srcData, mac);
        HKS_LOG_D("leave mac with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientMac(key, paramSet, srcData, mac);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    return HKS_ERROR_NOT_SUPPORTED;
#endif
#else
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)mac;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksHash(const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *hash)
{
#ifdef HKS_SUPPORT_API_HASH
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((paramSet == NULL) || (srcData == NULL) || (hash == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksLocalHash(paramSet, srcData, hash);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)paramSet;
    (void)srcData;
    (void)hash;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetKeyInfoList(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
#ifdef HKS_SUPPORT_API_GET_KEY_INFO_LIST
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyInfoList == NULL) || (listCount == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetKeyInfoList(paramSet, keyInfoList, listCount);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)paramSet;
    (void)keyInfoList;
    (void)listCount;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

#ifdef HKS_SUPPORT_API_ATTEST_KEY
static int32_t ConstructNewAttestParamSet(const struct HksParamSet *paramSet, enum HksAttestationMode mode,
    struct HksParamSet **newParamSet)
{
    int32_t ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("check paramSet fail");
        return ret;
    }
    ret = HksInitParamSet(newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init paramSet fail");
        return ret;
    }
    do {
        ret = HksAddParams(*newParamSet, paramSet->params, paramSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("copy params fail");
            break;
        }
        struct HksParam attestMode = {
            .tag = HKS_TAG_ATTESTATION_MODE,
            .uint32Param = mode,
        };
        ret = HksAddParams(*newParamSet, &attestMode, 1);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add param attestMode fail");
            break;
        }
        ret = HksBuildParamSet(newParamSet);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("build paramSet fail");
            break;
        }
        return HKS_SUCCESS;
    } while (false);
    HksFreeParamSet(newParamSet);
    return ret;
}
#endif

HKS_API_EXPORT int32_t HksAttestKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
#ifdef HKS_SUPPORT_API_ATTEST_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (paramSet == NULL) || (certChain == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = ConstructNewAttestParamSet(paramSet, HKS_ATTESTATION_MODE_DEFAULT, &newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet for attest key fail");
        return ret;
    }

    ret = HksClientAttestKey(keyAlias, newParamSet, certChain, false);
    HksFreeParamSet(&newParamSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksAnonAttestKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
#ifdef HKS_SUPPORT_API_ATTEST_KEY
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (paramSet == NULL) || (certChain == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = ConstructNewAttestParamSet(paramSet, HKS_ATTESTATION_MODE_ANONYMOUS, &newParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct new paramSet for anonn attest key fail");
        return ret;
    }

    ret = HksClientAttestKey(keyAlias, newParamSet, certChain, true);
    HksFreeParamSet(&newParamSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetCertificateChain(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

HKS_API_EXPORT int32_t HksWrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedData)
{
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)paramSet;
    (void)wrappedData;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

HKS_API_EXPORT int32_t HksUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksBlob *wrappedData, const struct HksParamSet *paramSet)
{
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)paramSet;
    (void)wrappedData;
    return HKS_ERROR_API_NOT_SUPPORTED;
}

HKS_API_EXPORT int32_t HksBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n)
{
#ifdef HKS_SUPPORT_API_BN_EXP_MOD
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((x == NULL) || (a == NULL) || (e == NULL) || (n == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksLocalBnExpMod(x, a, e, n);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)x;
    (void)a;
    (void)e;
    (void)n;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

/*
 * Currently, the device certificate and device key are implemented using stubs.
 * By default, the device key exists.
*/
HKS_API_EXPORT int32_t HcmIsDeviceKeyExist(const struct HksParamSet *paramSet)
{
    (void)paramSet;
    return HKS_SUCCESS;
}

HKS_API_EXPORT int32_t HksValidateCertChain(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut)
{
#ifdef HKS_SUPPORT_API_ATTEST_KEY
    HKS_LOG_D("enter validate cert chain");
    if ((paramSetOut == NULL) || (certChain == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientValidateCertChain(certChain, paramSetOut);
    HKS_LOG_D("leave validate cert chain, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)certChain;
    (void)paramSetOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((keyAlias == NULL) || (paramSet == NULL) || (handle == NULL)) { /* token can be null */
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientInit(keyAlias, paramSet, handle, token);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
}

HKS_API_EXPORT int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((handle == NULL) || (paramSet == NULL) || (inData == NULL) || (outData == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientUpdate(handle, paramSet, inData, outData);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
}

HKS_API_EXPORT int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((handle == NULL) || (paramSet == NULL) || (inData == NULL) || (outData == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientFinish(handle, paramSet, inData, outData);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
}

HKS_API_EXPORT int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if ((handle == NULL) || (paramSet == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientAbort(handle, paramSet);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
}

HKS_API_EXPORT int32_t HksExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey)
{
#ifdef HKS_SUPPORT_CHIPSET_PLATFORM_DECRYPT
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(salt), HKS_ERROR_INVALID_ARGUMENT, "invalid salt")
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(publicKey), HKS_ERROR_INVALID_ARGUMENT, "invalid publicKey")
    int32_t ret = HksClientExportChipsetPlatformPublicKey(salt, scene, publicKey);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
#else
    (void)(salt);
    (void)(scene);
    (void)(publicKey);
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData)
{
    HKS_LOG_D("enter %" LOG_PUBLIC "s", __func__);
    if (paramSet == NULL || outData == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientListAliases(paramSet, outData);
    HKS_LOG_D("leave %" LOG_PUBLIC "s, result = %" LOG_PUBLIC "d", __func__, ret);
    return ret;
}