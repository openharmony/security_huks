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
#include "hks_crypto_hal.h"
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_type_enum.h"
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

HKS_API_EXPORT int32_t HksRegisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter RegisterProvider");
    HKS_LOG_E("hks_api.c ======== enter RegisterProvider");
    if ((paramSetIn == NULL) || (name == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientRegisterProvider(name, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave RegisterProvider, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)name;
    (void)paramSetIn;
    return 0;
#endif
}

HKS_API_EXPORT int32_t HksUnregisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter UnregisterProvider");
    if (name == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientUnregisterProvider(name, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave UnregisterProvider, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)name;
    (void)paramSetIn;
    return 0;
#endif
}

HKS_API_EXPORT int32_t HksExportProviderCertificates(const struct HksBlob *providerName, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter HksExportProviderCertificates");
    HKS_LOG_E("hks_api.c ======== enter HksExportProviderCertificates");
    if ((paramSetIn == NULL) || (providerName == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientExportProviderCertificates(providerName, paramSetIn, certSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave HksExportProviderCertificates, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)providerName;
    (void)paramSetIn;
    return 0;
#endif
}

HKS_API_EXPORT int32_t HksExportCertificate(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter HksExportCertificate");
    HKS_LOG_E("hks_api.c ======== enter HksExportCertificate");
    if ((paramSetIn == NULL) || (index == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientExportCertificate(index, paramSetIn, certSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave HksExportCertificate, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    return 0;
#endif
}

HKS_API_EXPORT int32_t HksAuthUkeyPinWrapper(const struct HksBlob *index, const struct HksParamSet *paramSetIn, uint32_t *retryCount)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter HksAuthUkeyPinWrapper");
    if ((index == NULL) || (paramSetIn == NULL) || (retryCount == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t outStatus = 0;
    int32_t ret = HksClientAuthUkeyPin(index, paramSetIn, &outStatus, retryCount);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave AuthUkeyPin, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)retryCount;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}


HKS_API_EXPORT int32_t HksAuthUkeyPin(const struct HksBlob *index, const struct HksParamSet *paramSetIn, uint32_t *outStatus, uint32_t *retryCount)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter AuthUkeyPin");
    if ((index == NULL) || (paramSetIn == NULL) || (outStatus == NULL) || (retryCount == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientAuthUkeyPin(index, paramSetIn, outStatus, retryCount);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave AuthUkeyPin, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)retryCount;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}
// NAPI接口
HKS_API_EXPORT int32_t HksGetUkeyPinAuthState(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter GetUkeyPinAuthState");
    if ((index == NULL) || (paramSetIn == NULL) || (paramSetOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetUkeyPinAuthState(index, paramSetIn, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GetUkeyPinAuthState, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)paramSetOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksOpenRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksBlob *remoteHandleOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter OpenRemoteHandle");
    if ((index == NULL) || (paramSetIn == NULL) || (remoteHandleOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientOpenRemoteHandle(index, paramSetIn, remoteHandleOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave OpenRemoteHandle, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)remoteHandleOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksBlob *remoteHandleOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter GetRemoteHandle");
    if ((index == NULL) || (paramSetIn == NULL) || (remoteHandleOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetRemoteHandle(index, paramSetIn, remoteHandleOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GetRemoteHandle, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)remoteHandleOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}
HKS_API_EXPORT int32_t HksCloseRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter CloseRemoteHandle");
    if ((index == NULL) || (paramSetIn == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientCloseRemoteHandle(index, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave CloseRemoteHandle, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)remoteHandleOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetPinAuthState(const struct HksBlob *index, uint32_t *stateOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter GetPinAuthState");
    if ((index == NULL) || (stateOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetPinAuthState(index, stateOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GetPinAuthState, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)stateOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}
HKS_API_EXPORT int32_t HksClearPinAuthState(const struct HksBlob *index)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter ClearPinAuthState");
    if (index == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientClearPinAuthState(index);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ClearPinAuthState, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

// 签名验签
HKS_API_EXPORT int32_t HksUkeySign(const struct HksBlob *index, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter UkeySign");
    if ((index == NULL) || (paramSetIn == NULL) || (srcData == NULL) || (signatureOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientUkeySign(index, paramSetIn, srcData, signatureOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave UkeySign, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)srcData;
    (void)signatureOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksUkeyVerify(const struct HksBlob *index, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
#ifdef L2_STANDARD
    HKS_LOG_D("enter UkeyVerify");
    if ((index == NULL) || (paramSetIn == NULL) || (srcData == NULL) || (signatureOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientUkeyVerify(index, paramSetIn, srcData, signatureOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave UkeyVerify, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)index;
    (void)paramSetIn;
    (void)srcData;
    (void)signatureOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksGetSdkVersion(struct HksBlob *sdkVersion)
{
    if ((sdkVersion == NULL) || (sdkVersion->data == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    uint32_t versionLen = strlen(HKS_SDK_VERSION);
    if (sdkVersion->size < (versionLen + 1)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(sdkVersion->data, sdkVersion->size, HKS_SDK_VERSION, versionLen),
        HKS_ERROR_INSUFFICIENT_MEMORY, "copy sdkVersion data failed!")

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
    HKS_IF_NOT_SUCC_LOGE(ret, "leave refresh key info, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

static int32_t CheckifNeedOverrideKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn)
{
    struct HksParam *isKeyOverride = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_OVERRIDE, &isKeyOverride);
    if (ret == HKS_SUCCESS && !isKeyOverride->boolParam) {
        ret = HksClientKeyExist(keyAlias, paramSetIn);
        if (ret == HKS_SUCCESS) {
            return HKS_ERROR_CODE_KEY_ALREADY_EXIST;
        } else if (ret != HKS_ERROR_NOT_EXIST) {
            return ret;
        }
    }
    
    return HKS_SUCCESS;
}

HKS_API_EXPORT int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
#ifdef HKS_SUPPORT_API_GENERATE_KEY
    HKS_LOG_D("enter GenerateKey");
    struct HksParam *storageFlag = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_STORAGE_FLAG, &storageFlag);
    if ((ret == HKS_SUCCESS) && (storageFlag->uint32Param == HKS_STORAGE_TEMP)) {
        if ((paramSetIn == NULL) || (paramSetOut == NULL)) {
            return HKS_ERROR_NULL_POINTER;
        }
        ret = HksLocalGenerateKey(paramSetIn, paramSetOut);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave generate temp key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }

    if ((paramSetIn == NULL) || (keyAlias == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    ret = CheckifNeedOverrideKey(keyAlias, paramSetIn);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksClientGenerateKey(keyAlias, paramSetIn, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GenerateKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter ImportKey");
    if ((keyAlias == NULL) || (paramSet == NULL) || (key == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = CheckifNeedOverrideKey(keyAlias, paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksImportKeyAdapter(keyAlias, paramSet, key);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ImportKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter ImportWrappedKey");
    if ((keyAlias == NULL) || (wrappingKeyAlias == NULL)|| (paramSet == NULL) || (wrappedKeyData == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = CheckifNeedOverrideKey(keyAlias, paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksClientImportWrappedKey(keyAlias, wrappingKeyAlias, paramSet, wrappedKeyData);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ImportWrappedKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter ExportPublicKey");
    if ((keyAlias == NULL) || (key == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksExportPublicKeyAdapter(keyAlias, paramSet, key);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ExportPublicKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter DeleteKey");
    HKS_IF_NULL_RETURN(keyAlias, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientDeleteKey(keyAlias, paramSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave DeleteKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter GetKeyParamSet");
    if ((keyAlias == NULL) || (paramSetOut == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetKeyParamSet(keyAlias, paramSetIn, paramSetOut);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GetKeyParamSet, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter KeyExist");
    HKS_IF_NULL_RETURN(keyAlias, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientKeyExist(keyAlias, paramSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave KeyExist, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter GenerateRandom");
    HKS_IF_NULL_RETURN(random, HKS_ERROR_NULL_POINTER)
    int32_t ret = HksClientGenerateRandom(random, paramSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GenerateRandom, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Sign");
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (signature == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        return HksLocalSign(key, paramSet, srcData, signature);
    }

    ret = HksClientSign(key, paramSet, srcData, signature);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Sign, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Verify");
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (signature == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalVerify(key, paramSet, srcData, signature);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave verify with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
    ret = HksClientVerify(key, paramSet, srcData, signature);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Verify, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Encrypt");
    if ((key == NULL) || (paramSet == NULL) || (plainText == NULL) || (cipherText == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalEncrypt(key, paramSet, plainText, cipherText);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave encrypt with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientEncrypt(key, paramSet, plainText, cipherText);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Encrypt, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Decrypt");
    if ((key == NULL) || (paramSet == NULL) || (cipherText == NULL) || (plainText == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalDecrypt(key, paramSet, cipherText, plainText);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave decrypt with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientDecrypt(key, paramSet, cipherText, plainText);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Decrypt, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter AgreeKey");
    if ((paramSet == NULL) || (privateKey == NULL) || (peerPublicKey == NULL) || (agreedKey == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalAgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave agree key with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }

    ret = HksAgreeKeyAdapter(paramSet, privateKey, peerPublicKey, agreedKey);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave AgreeKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter DeriveKey");
    if ((paramSet == NULL) || (mainKey == NULL) || (derivedKey == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalDeriveKey(paramSet, mainKey, derivedKey);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave derive key with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientDeriveKey(paramSet, mainKey, derivedKey);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave DeriveKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Mac");
    if ((key == NULL) || (paramSet == NULL) || (srcData == NULL) || (mac == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *isKeyAlias = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_KEY_ALIAS, &isKeyAlias);
    if ((ret == HKS_SUCCESS) && (!isKeyAlias->boolParam)) {
        ret = HksLocalMac(key, paramSet, srcData, mac);
        HKS_IF_NOT_SUCC_LOGE(ret, "leave mac with plain key, result = %" LOG_PUBLIC "d", ret);
        return ret;
    }
#ifndef _CUT_AUTHENTICATE_
    ret = HksClientMac(key, paramSet, srcData, mac);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Mac, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Hash");
    if ((paramSet == NULL) || (srcData == NULL) || (hash == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksLocalHash(paramSet, srcData, hash);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Hash, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter GetKeyInfoList");
    if ((keyInfoList == NULL) || (listCount == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientGetKeyInfoList(paramSet, keyInfoList, listCount);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave GetKeyInfoList, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter AttestKey");
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
    HKS_IF_NOT_SUCC_LOGE(ret, "leave AttestKey, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter AnonAttestKey");
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
    HKS_IF_NOT_SUCC_LOGE(ret, "leave AnonAttestKey, result = %" LOG_PUBLIC "d", ret);
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
    (void)targetKeyAlias;
#ifdef L2_STANDARD
    HKS_LOG_D("enter WrapKey");
    if (keyAlias == NULL || paramSet == NULL || wrappedData == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientWrapKey(keyAlias, paramSet, wrappedData);
    HKS_LOG_D("leave WrapKey, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)wrappedData;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksBlob *wrappedData, const struct HksParamSet *paramSet)
{
    (void)targetKeyAlias;
#ifdef L2_STANDARD
    HKS_LOG_D("enter UnwrapKey");
    if (keyAlias == NULL || paramSet == NULL || wrappedData == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientUnwrapKey(keyAlias, paramSet, wrappedData);
    HKS_LOG_D("leave UnwrapKey, result = %" LOG_PUBLIC "d", ret);
    return ret;
#else
    (void)keyAlias;
    (void)paramSet;
    (void)wrappedData;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

HKS_API_EXPORT int32_t HksBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n)
{
#ifdef HKS_SUPPORT_API_BN_EXP_MOD
    HKS_LOG_D("enter BnExpMod");
    if ((x == NULL) || (a == NULL) || (e == NULL) || (n == NULL)) {
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksLocalBnExpMod(x, a, e, n);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave BnExpMod, result = %" LOG_PUBLIC "d", ret);
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
    HKS_IF_NOT_SUCC_LOGE(ret, "leave validate cert chain, result = %" LOG_PUBLIC "d", ret);
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
    HKS_LOG_D("enter Init");
    if ((keyAlias == NULL) || (paramSet == NULL) || (handle == NULL)) { /* token can be null */
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientInit(keyAlias, paramSet, handle, token);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Init, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("enter Update");
    if ((handle == NULL) || (paramSet == NULL) || (inData == NULL) || (outData == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientUpdate(handle, paramSet, inData, outData);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Update, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("enter Finish");
    if ((handle == NULL) || (paramSet == NULL) || (inData == NULL) || (outData == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientFinish(handle, paramSet, inData, outData);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Finish, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    HKS_LOG_D("enter Abort");
    if ((handle == NULL) || (paramSet == NULL)) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksClientAbort(handle, paramSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave Abort, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData)
{
    HKS_LOG_D("enter ListAliases");
    if (paramSet == NULL || outData == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientListAliases(paramSet, outData);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ListAliases, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksRenameKeyAlias(const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias)
{
    HKS_LOG_D("enter RenameKeyAlias");
    if (oldKeyAlias == NULL || paramSet == NULL || newKeyAlias == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientRenameKeyAlias(oldKeyAlias, paramSet, newKeyAlias);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave RenameKeyAlias, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT int32_t HksChangeStorageLevel(const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *destParamSet)
{
    HKS_LOG_D("enter ChangeStorageLevel");
    if (keyAlias == NULL || srcParamSet == NULL || destParamSet == NULL) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HksClientChangeStorageLevel(keyAlias, srcParamSet, destParamSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "leave ChangeStorageLevel, result = %" LOG_PUBLIC "d", ret);
    return ret;
}

HKS_API_EXPORT const char *HksGetErrorMsg(void)
{
    HKS_LOG_D("enter GetErrorMsg");

#ifdef L2_STANDARD
    return HksGetThreadErrorMsg();
#endif
    return NULL;
}