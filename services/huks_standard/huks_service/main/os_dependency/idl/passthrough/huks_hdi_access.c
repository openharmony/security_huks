/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "hdf_base.h"
#include "hks_error_code.h"
#include <stdint.h>
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "huks_access.h"

#include <pthread.h>

#include "hks_cfi.h"
#include "huks_hdi.h"

#include "wrapper/huks_hdi_wrapper.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_cfi.h"
#include "hks_check_paramset.h"

enum HdiVersion {
    INVALID = 0,
    V1_0 = 1,
    V1_1 = 2,
    V1_2 = 3,
};

typedef struct HuksHdiWrapper *(*GetWrapperFunc)(void);

typedef struct {
    enum HdiVersion version;
    GetWrapperFunc func;
} WrapperInstance;

static const WrapperInstance WRAPPER_INSTANCE_LIST[] = {
    { V1_2, HuksHdiWrapperV1_2_Get },
    { V1_1, HuksHdiWrapperV1_1_Get },
};

static enum HdiVersion g_hdiInstanceVersion;
static struct HuksHdiWrapper *g_wrapperInstance = NULL;
static pthread_mutex_t g_hdiProxyMutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef _CUT_AUTHENTICATE_

ENABLE_CFI(static int32_t InitWrapperInstance())
{
    for (uint32_t i = 0; i < (sizeof(WRAPPER_INSTANCE_LIST) / sizeof(WrapperInstance)); i++) {
        g_wrapperInstance = WRAPPER_INSTANCE_LIST[i].func();
        if (g_wrapperInstance != NULL) {
            g_hdiInstanceVersion = WRAPPER_INSTANCE_LIST[i].version;
            return HKS_SUCCESS;
        }
    }
    g_hdiInstanceVersion = INVALID;
    return HKS_ERROR_NULL_POINTER;
}

static int32_t InitHdiProxyInstance()
{
    if (g_wrapperInstance != NULL) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&g_hdiProxyMutex);
    HKS_IF_NOT_SUCC_LOG_ERRNO_RETURN("g_hdiProxyMutex pthread_mutex_lock failed", ret);

    if (g_wrapperInstance != NULL) {
        (void)pthread_mutex_unlock(&g_hdiProxyMutex);
        return HKS_SUCCESS;
    }

    ret = InitWrapperInstance();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InitHdiInstance failed");
        (void)pthread_mutex_unlock(&g_hdiProxyMutex);
        return HKS_ERROR_NULL_POINTER;
    }

    (void)pthread_mutex_unlock(&g_hdiProxyMutex);
    return HKS_SUCCESS;
}

static bool IsCallable(enum HdiVersion funcVersion)
{
    return (g_hdiInstanceVersion >= funcVersion);
}

ENABLE_CFI(int32_t HuksAccessModuleInit(void))
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->ModuleInit, HKS_ERROR_NULL_POINTER,
        "Module Init function is null pointer")

    return g_wrapperInstance->ModuleInit();
}

ENABLE_CFI(int32_t HuksAccessModuleDestroy(void))
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->ModuleDestroy, HKS_ERROR_NULL_POINTER,
        "Module Destroy function is null pointer")

    return g_wrapperInstance->ModuleDestroy();
}

ENABLE_CFI(int32_t HuksAccessRefresh(void))
{
    return HKS_SUCCESS;
}

static int32_t HdiProxyGenerateKey(const struct HuksBlob* keyAlias, const struct HuksParamSet* paramSet,
    const struct HuksBlob* keyIn, struct HuksBlob* keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->GenerateKey, HKS_ERROR_NULL_POINTER,
        "GenerateKey function is null pointer")

    return g_wrapperInstance->GenerateKey(keyAlias, paramSet, keyIn, keyOut);
}

ENABLE_CFI(int32_t HuksAccessGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSetIn, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_GENERATEKEY(keyAlias, paramSetInNew, keyIn, keyOut, ret, HdiProxyGenerateKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyImportKey(const struct HuksBlob *keyAlias, const struct HuksBlob *key,
    const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->ImportKey, HKS_ERROR_NULL_POINTER,
        "ImportKey function is null pointer")
    return g_wrapperInstance->ImportKey(keyAlias, key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_IMPORTKEY(keyAlias, key, paramSetInNew, keyOut, ret, HdiProxyImportKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyImportWrappedKey(const struct HuksBlob *wrappingKeyAlias, const struct HuksBlob *key,
    const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->ImportWrappedKey, HKS_ERROR_NULL_POINTER,
        "ImportWrappedKey function is null pointer")
    return g_wrapperInstance->ImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_IMPORTWRAPPEDKEY(wrappingKeyAlias, key, wrappedKeyData, paramSetInNew, keyOut, ret,
        HdiProxyImportWrappedKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyExportPublicKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->ExportPublicKey, HKS_ERROR_NULL_POINTER,
        "ExportPublicKey function is null pointer")
    return g_wrapperInstance->ExportPublicKey(key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_EXPORTPUBLICKEY(key, paramSetInNew, keyOut, ret, HdiProxyExportPublicKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyInit(const struct  HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *handle, struct HuksBlob *token)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Init, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")
    return g_wrapperInstance->Init(key, paramSet, handle, token);
}

ENABLE_CFI(int32_t HuksAccessInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_INIT(key, paramSetInNew, handle, token, ret, HdiProxyInit)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyUpdate(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Update, HKS_ERROR_NULL_POINTER,
        "Update function is null pointer")
    return g_wrapperInstance->Update(handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_UPDATE(handle, paramSetInNew, inData, outData, ret, HdiProxyUpdate)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyFinish(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Finish, HKS_ERROR_NULL_POINTER,
        "Finish function is null pointer")
    return g_wrapperInstance->Finish(handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_FINISH(handle, paramSetInNew, inData, outData, ret, HdiProxyFinish);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyAbort(const struct HuksBlob *handle, const struct HuksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Abort, HKS_ERROR_NULL_POINTER,
        "Abort function is null pointer")
    return g_wrapperInstance->Abort(handle, paramSet);
}

ENABLE_CFI(int32_t HuksAccessAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_ABORT(handle, paramSetInNew, ret, HdiProxyAbort);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyCheckKeyValidity(const struct HuksParamSet* paramSet, const struct HuksBlob* key)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->CheckKeyValidity, HKS_ERROR_NULL_POINTER,
        "GetKeyProperties function is null pointer")

    return g_wrapperInstance->CheckKeyValidity(paramSet, key);
}

ENABLE_CFI(int32_t HuksAccessGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_CHECKKEYVALIDITY(paramSetInNew, key, ret, HdiProxyCheckKeyValidity)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessGetAbility(int funcType))
{
    (void)(funcType);
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksAccessGetHardwareInfo(void))
{
    return HKS_SUCCESS;
}

static int32_t HdiProxySign(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *signature)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Sign, HKS_ERROR_NULL_POINTER,
        "Sign function is null pointer")
    return g_wrapperInstance->Sign(key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_SIGN(key, paramSetInNew, srcData, signature, ret, HdiProxySign)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyVerify(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, const struct HuksBlob *signature)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Verify, HKS_ERROR_NULL_POINTER,
        "Verify function is null pointer")
    return g_wrapperInstance->Verify(key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_VERIFY(key, paramSetInNew, srcData, signature, ret, HdiProxyVerify)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyEncrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *plainText, struct HuksBlob *cipherText)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Encrypt, HKS_ERROR_NULL_POINTER,
        "Encrypt function is null pointer")
    return g_wrapperInstance->Encrypt(key, paramSet, plainText, cipherText);
}

ENABLE_CFI(int32_t HuksAccessEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_ENCRYPT(key, paramSetInNew, plainText, cipherText, ret, HdiProxyEncrypt)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyDecrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *cipherText, struct HuksBlob *plainText)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Decrypt, HKS_ERROR_NULL_POINTER,
        "Decrypt function is null pointer")
    return g_wrapperInstance->Decrypt(key, paramSet, cipherText, plainText);
}

ENABLE_CFI(int32_t HuksAccessDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_DECRYPT(key, paramSetInNew, cipherText, plainText, ret, HdiProxyDecrypt)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyAgreeKey(const struct HuksParamSet *paramSet, const struct HuksBlob *privateKey,
    const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->AgreeKey, HKS_ERROR_NULL_POINTER,
        "AgreeKey function is null pointer")
    return g_wrapperInstance->AgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
}

ENABLE_CFI(int32_t HuksAccessAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_AGREEKEY(paramSetInNew, privateKey, peerPublicKey, agreedKey, ret, HdiProxyAgreeKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyDeriveKey(const struct HuksParamSet *paramSet, const struct HuksBlob *kdfKey,
    struct HuksBlob *derivedKey)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->DeriveKey, HKS_ERROR_NULL_POINTER,
        "DeriveKey function is null pointer")
    return g_wrapperInstance->DeriveKey(paramSet, kdfKey, derivedKey);
}

ENABLE_CFI(int32_t HuksAccessDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_DERIVEKEY(paramSetInNew, kdfKey, derivedKey, ret, HdiProxyDeriveKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyMac(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *mac)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Mac, HKS_ERROR_NULL_POINTER,
        "Mac function is null pointer")
    return g_wrapperInstance->Mac(key, paramSet, srcData, mac);
}

ENABLE_CFI(int32_t HuksAccessMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_MAC(key, paramSetInNew, srcData, mac, ret, HdiProxyMac)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

static int32_t HdiProxyGetErrorInfo(struct HuksBlob *errorInfo)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->GetErrorInfo, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_wrapperInstance->GetErrorInfo(errorInfo);
}

ENABLE_CFI(int32_t HuksAccessGetErrorInfo(struct HksBlob *errorInfo))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_GETERRORINFO(errorInfo, ret, HdiProxyGetErrorInfo)
    return ret;
}

static int32_t HdiProxyGetStatInfo(struct HuksBlob *statInfo)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->GetStatInfo, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_wrapperInstance->GetStatInfo(statInfo);
}

ENABLE_CFI(int32_t HuksAccessGetStatInfo(struct HksBlob *statInfo))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_GETSTATINFO(statInfo, ret, HdiProxyGetStatInfo)
    return ret;
}
#ifdef HKS_ENABLE_UPGRADE_KEY
static int32_t HdiProxyUpgradeKey(const struct HuksBlob *oldKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *newKey)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->UpgradeKey, HKS_ERROR_NULL_POINTER,
        "Change key owner function is null pointer")
    return g_wrapperInstance->UpgradeKey(oldKey, paramSet, newKey);
}

ENABLE_CFI(int32_t HuksAccessUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_UPGRADEKEY(oldKey, paramSetInNew, newKey, ret, HdiProxyUpgradeKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
static int32_t HdiProxyAttestKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *certChain)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->AttestKey, HKS_ERROR_NULL_POINTER,
        "AttestKey function is null pointer")
    return g_wrapperInstance->AttestKey(key, paramSet, certChain);
}

ENABLE_CFI(int32_t HuksAccessAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain))
{
    int32_t ret = HDF_FAILURE;
    struct HksParamSet *paramSetInNew = NULL;
    ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    HDI_CONVERTER_FUNC_ATTESTKEY(key, paramSetInNew, certChain, ret, HdiProxyAttestKey)
    HksFreeParamSet(&paramSetInNew);
    return ret;
}
#endif

static int32_t HdiProxyEncapsulate(const struct HuksParamSet *paramSet, const struct HuksParamSet *sharedKeyParamSet,
    struct HuksEncapsulationResult *encapResult)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_2), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Encapsulate, HKS_ERROR_NULL_POINTER,
        "Encapsulate function is null pointer")
    return g_wrapperInstance->Encapsulate(paramSet, sharedKeyParamSet, encapResult);
}

ENABLE_CFI(int32_t HuksAccessEncapsulate(const struct HksParamSet *paramSet, const struct HksParamSet *sharedKeyParam,
    struct HksEncapsulationResult *encapResult))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_ENCAPSULATE(paramSet, sharedKeyParam, encapResult, ret, HdiProxyEncapsulate)
    return ret;
}

static int32_t HdiProxyDecapsulate(const struct HuksParamSet *paramSet, const struct HuksParamSet *sharedKeyParamSet,
    const struct HuksBlob *encapsulatedData, struct HuksBlob *sharedSecret)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_2), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->Decapsulate, HKS_ERROR_NULL_POINTER,
        "Decapsulate function is null pointer")
    return g_wrapperInstance->Decapsulate(paramSet, sharedKeyParamSet, encapsulatedData, sharedSecret);
}

ENABLE_CFI(int32_t HuksAccessDecapsulate(const struct HksParamSet *paramSet, const struct HksParamSet *sharedKeyParam,
    struct HksBlob *encapsData, struct HksBlob *hdiSharedSecret))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_DECAPSULATE(paramSet, sharedKeyParam, encapsData, hdiSharedSecret, ret,
        HdiProxyDecapsulate)
    return ret;
}

#endif /* _CUT_AUTHENTICATE_ */

static int32_t HdiProxyGenerateRandom(const struct HuksParamSet *paramSet, struct HuksBlob *random)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_wrapperInstance->GenerateRandom, HKS_ERROR_NULL_POINTER,
        "GenerateRandom function is null pointer")
    return g_wrapperInstance->GenerateRandom(paramSet, random);
}

ENABLE_CFI(int32_t HuksAccessGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_GENERATERANDOM(paramSet, random, ret, HdiProxyGenerateRandom)
    return ret;
}
