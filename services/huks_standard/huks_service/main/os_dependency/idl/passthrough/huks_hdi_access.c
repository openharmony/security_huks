/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "v1_1/ihuks.h"
#include "v1_1/ihuks_types.h"

#include "huks_hdi_v1_0_adapter.h"
#include "huks_hdi_v1_1_adapter.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_cfi.h"

// new veison must in order, Higher versions cannot use interfaces from lower versions
enum HdiVersion {
    INVALID = 0,
    V1_0 = 1,
    V1_1 = 2,
};

typedef struct IHuks *(*GetHdiInstanceFunc)();

typedef struct {
    enum HdiVersion version;
    GetHdiInstanceFunc func;
} HdiInstance;

// version sequence must in order, get instance from front to back
static const HdiInstance HDI_INSTANCE_LIST[] = {
    { V1_1, GeyHuksHdiInstanceV1_1 },
    { V1_0, GeyHuksHdiInstanceV1_0 },
};

static enum HdiVersion g_hdiInstanceVersion;
static struct IHuks *g_hksHdiProxyInstance = NULL;
static pthread_mutex_t g_hdiProxyMutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef _CUT_AUTHENTICATE_

ENABLE_CFI(static int32_t InitHdiInstance())
{
    for (uint32_t i = 0; i < (sizeof(HDI_INSTANCE_LIST)/sizeof(HdiInstance)); i++) {
        g_hksHdiProxyInstance = HDI_INSTANCE_LIST[i].func();
        if (g_hksHdiProxyInstance != NULL) {
            g_hdiInstanceVersion = HDI_INSTANCE_LIST[i].version;
            return HKS_SUCCESS;
        }
    }
    g_hdiInstanceVersion = INVALID;
    return HKS_ERROR_NULL_POINTER;
}

static int32_t InitHdiProxyInstance()
{
    if (g_hksHdiProxyInstance != NULL) {
        return HKS_SUCCESS;
    }

    int32_t ret = pthread_mutex_lock(&g_hdiProxyMutex);
    HKS_IF_NOT_SUCC_LOG_ERRNO_RETURN("g_hdiProxyMutex pthread_mutex_lock failed", ret);

    if (g_hksHdiProxyInstance != NULL) {
        (void)pthread_mutex_unlock(&g_hdiProxyMutex);
        return HKS_SUCCESS;
    }

    ret = InitHdiInstance();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("IHuksGet hdi huks service failed");
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

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->ModuleInit, HKS_ERROR_NULL_POINTER,
        "Module Init function is null pointer")

    return g_hksHdiProxyInstance->ModuleInit(g_hksHdiProxyInstance);
}

ENABLE_CFI(int32_t HuksAccessModuleDestroy(void))
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->ModuleDestroy, HKS_ERROR_NULL_POINTER,
        "Module Init function is null pointer")

    return g_hksHdiProxyInstance->ModuleDestroy(g_hksHdiProxyInstance);
}

ENABLE_CFI(int32_t HuksAccessRefresh(void))
{
    return HKS_SUCCESS;
}

static int32_t HdiProxyGenerateKey(const struct HuksBlob* keyAlias, const struct HuksParamSet* paramSet,
    const struct HuksBlob* keyIn, struct HuksBlob* keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->GenerateKey, HKS_ERROR_NULL_POINTER,
        "GenerateKey function is null pointer")

    return g_hksHdiProxyInstance->GenerateKey(g_hksHdiProxyInstance, keyAlias, paramSet, keyIn, keyOut);
}

ENABLE_CFI(int32_t HuksAccessGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_GENERATEKEY(keyAlias, paramSetIn, keyIn, keyOut, ret, HdiProxyGenerateKey)
    return ret;
}

static int32_t HdiProxyImportKey(const struct HuksBlob *keyAlias, const struct HuksBlob *key,
    const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->ImportKey, HKS_ERROR_NULL_POINTER,
        "ImportKey function is null pointer")
    return g_hksHdiProxyInstance->ImportKey(g_hksHdiProxyInstance, keyAlias, key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_IMPORTKEY(keyAlias, key, paramSet, keyOut, ret, HdiProxyImportKey)
    return ret;
}

static int32_t HdiProxyImportWrappedKey(const struct HuksBlob *wrappingKeyAlias, const struct HuksBlob *key,
    const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->ImportWrappedKey, HKS_ERROR_NULL_POINTER,
        "ImportWrappedKey function is null pointer")
    return g_hksHdiProxyInstance->ImportWrappedKey(g_hksHdiProxyInstance, wrappingKeyAlias, key, wrappedKeyData,
        paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_IMPORTWRAPPEDKEY(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut, ret,
        HdiProxyImportWrappedKey)
    return ret;
}

static int32_t HdiProxyExportPublicKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *keyOut)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->ExportPublicKey, HKS_ERROR_NULL_POINTER,
        "ExportPublicKey function is null pointer")
    return g_hksHdiProxyInstance->ExportPublicKey(g_hksHdiProxyInstance, key, paramSet, keyOut);
}

ENABLE_CFI(int32_t HuksAccessExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_EXPORTPUBLICKEY(key, paramSet, keyOut, ret, HdiProxyExportPublicKey)
    return ret;
}

static int32_t HdiProxyInit(const struct  HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *handle, struct HuksBlob *token)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Init, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")
    return g_hksHdiProxyInstance->Init(g_hksHdiProxyInstance, key, paramSet, handle, token);
}

ENABLE_CFI(int32_t HuksAccessInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_INIT(key, paramSet, handle, token, ret, HdiProxyInit)
    return ret;
}

static int32_t HdiProxyUpdate(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Update, HKS_ERROR_NULL_POINTER,
        "Update function is null pointer")
    return g_hksHdiProxyInstance->Update(g_hksHdiProxyInstance, handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_UPDATE(handle, paramSet, inData, outData, ret, HdiProxyUpdate)
    return ret;
}

static int32_t HdiProxyFinish(const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Finish, HKS_ERROR_NULL_POINTER,
        "Finish function is null pointer")
    return g_hksHdiProxyInstance->Finish(g_hksHdiProxyInstance, handle, paramSet, inData, outData);
}

ENABLE_CFI(int32_t HuksAccessFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_FINISH(handle, paramSet, inData, outData, ret, HdiProxyFinish);
    return ret;
}

static int32_t HdiProxyAbort(const struct HuksBlob *handle, const struct HuksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Abort, HKS_ERROR_NULL_POINTER,
        "Abort function is null pointer")
    return g_hksHdiProxyInstance->Abort(g_hksHdiProxyInstance, handle, paramSet);
}

ENABLE_CFI(int32_t HuksAccessAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_ABORT(handle, paramSet, ret, HdiProxyAbort);
    return ret;
}

static int32_t HdiProxyCheckKeyValidity(const struct HuksParamSet* paramSet, const struct HuksBlob* key)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->CheckKeyValidity, HKS_ERROR_NULL_POINTER,
        "GetKeyProperties function is null pointer")

    return g_hksHdiProxyInstance->CheckKeyValidity(g_hksHdiProxyInstance, paramSet, key);
}

ENABLE_CFI(int32_t HuksAccessGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_CHECKKEYVALIDITY(paramSet, key, ret, HdiProxyCheckKeyValidity)
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

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Sign, HKS_ERROR_NULL_POINTER,
        "Sign function is null pointer")
    return g_hksHdiProxyInstance->Sign(g_hksHdiProxyInstance, key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_SIGN(key, paramSet, srcData, signature, ret, HdiProxySign)
    return ret;
}

static int32_t HdiProxyVerify(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, const struct HuksBlob *signature)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Verify, HKS_ERROR_NULL_POINTER,
        "Verify function is null pointer")
    return g_hksHdiProxyInstance->Verify(g_hksHdiProxyInstance, key, paramSet, srcData, signature);
}

ENABLE_CFI(int32_t HuksAccessVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_VERIFY(key, paramSet, srcData, signature, ret, HdiProxyVerify)
    return ret;
}

static int32_t HdiProxyEncrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *plainText, struct HuksBlob *cipherText)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Encrypt, HKS_ERROR_NULL_POINTER,
        "Encrypt function is null pointer")
    return g_hksHdiProxyInstance->Encrypt(g_hksHdiProxyInstance, key, paramSet, plainText, cipherText);
}

ENABLE_CFI(int32_t HuksAccessEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_ENCRYPT(key, paramSet, plainText, cipherText, ret, HdiProxyEncrypt)
    return ret;
}

static int32_t HdiProxyDecrypt(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *cipherText, struct HuksBlob *plainText)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Decrypt, HKS_ERROR_NULL_POINTER,
        "Decrypt function is null pointer")
    return g_hksHdiProxyInstance->Decrypt(g_hksHdiProxyInstance, key, paramSet, cipherText, plainText);
}

ENABLE_CFI(int32_t HuksAccessDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_DECRYPT(key, paramSet, cipherText, plainText, ret, HdiProxyDecrypt)
    return ret;
}

static int32_t HdiProxyAgreeKey(const struct HuksParamSet *paramSet, const struct HuksBlob *privateKey,
    const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->AgreeKey, HKS_ERROR_NULL_POINTER,
        "AgreeKey function is null pointer")
    return g_hksHdiProxyInstance->AgreeKey(g_hksHdiProxyInstance, paramSet, privateKey, peerPublicKey, agreedKey);
}

ENABLE_CFI(int32_t HuksAccessAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_AGREEKEY(paramSet, privateKey, peerPublicKey, agreedKey, ret, HdiProxyAgreeKey)
    return ret;
}

static int32_t HdiProxyDeriveKey(const struct HuksParamSet *paramSet, const struct HuksBlob *kdfKey,
    struct HuksBlob *derivedKey)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->DeriveKey, HKS_ERROR_NULL_POINTER,
        "DeriveKey function is null pointer")
    return g_hksHdiProxyInstance->DeriveKey(g_hksHdiProxyInstance, paramSet, kdfKey, derivedKey);
}

ENABLE_CFI(int32_t HuksAccessDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_DERIVEKEY(paramSet, kdfKey, derivedKey, ret, HdiProxyDeriveKey)
    return ret;
}

static int32_t HdiProxyMac(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *mac)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->Mac, HKS_ERROR_NULL_POINTER,
        "Mac function is null pointer")
    return g_hksHdiProxyInstance->Mac(g_hksHdiProxyInstance, key, paramSet, srcData, mac);
}

ENABLE_CFI(int32_t HuksAccessMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_MAC(key, paramSet, srcData, mac, ret, HdiProxyMac)
    return ret;
}

static int32_t HdiProxyGetErrorInfo(struct HuksBlob *errorInfo)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_1), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->GetErrorInfo, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_hksHdiProxyInstance->GetErrorInfo(g_hksHdiProxyInstance, errorInfo);
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

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->GetStatInfo, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_hksHdiProxyInstance->GetStatInfo(g_hksHdiProxyInstance, statInfo);
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

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->UpgradeKey, HKS_ERROR_NULL_POINTER,
        "Change key owner function is null pointer")
    return g_hksHdiProxyInstance->UpgradeKey(g_hksHdiProxyInstance, oldKey, paramSet, newKey);
}

ENABLE_CFI(int32_t HuksAccessUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_UPGRADEKEY(oldKey, paramSet, newKey, ret, HdiProxyUpgradeKey)
    return ret;
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
static int32_t HdiProxyAttestKey(const struct HuksBlob *key, const struct HuksParamSet *paramSet,
    struct HuksBlob *certChain)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->AttestKey, HKS_ERROR_NULL_POINTER,
        "AttestKey function is null pointer")
    return g_hksHdiProxyInstance->AttestKey(g_hksHdiProxyInstance, key, paramSet, certChain);
}

ENABLE_CFI(int32_t HuksAccessAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_ATTESTKEY(key, paramSet, certChain, ret, HdiProxyAttestKey)
    return ret;
}
#endif

#endif /* _CUT_AUTHENTICATE_ */

static int32_t HdiProxyGenerateRandom(const struct HuksParamSet *paramSet, struct HuksBlob *random)
{
    HKS_IF_NOT_SUCC_RETURN(InitHdiProxyInstance(), HKS_ERROR_NULL_POINTER)

    HKS_IF_NOT_TRUE_LOGE_RETURN(IsCallable(V1_0), HKS_ERROR_NOT_SUPPORTED,
        "global hdi version is %" LOG_PUBLIC "d", g_hdiInstanceVersion)

    HKS_IF_NULL_LOGE_RETURN(g_hksHdiProxyInstance->GenerateRandom, HKS_ERROR_NULL_POINTER,
        "GenerateRandom function is null pointer")
    return g_hksHdiProxyInstance->GenerateRandom(g_hksHdiProxyInstance, paramSet, random);
}

ENABLE_CFI(int32_t HuksAccessGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random))
{
    int32_t ret = HDF_FAILURE;
    HDI_CONVERTER_FUNC_GENERATERANDOM(paramSet, random, ret, HdiProxyGenerateRandom)
    return ret;
}
