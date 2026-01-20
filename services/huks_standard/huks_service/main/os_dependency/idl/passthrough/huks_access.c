/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "huks_access.h"

#include "hks_cfi.h"
#include "huks_core_hal.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_param.h"
#include "hks_check_paramset.h"
static struct HuksHdi *g_hksHalDevicePtr = NULL;

#ifndef _CUT_AUTHENTICATE_
ENABLE_CFI(int32_t HuksAccessModuleInit(void))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiModuleInit, HKS_ERROR_NULL_POINTER,
        "Module Init function is null pointer")

    return g_hksHalDevicePtr->HuksHdiModuleInit();
}

ENABLE_CFI(int32_t HuksAccessModuleDestroy(void))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiModuleDestroy, HKS_ERROR_NULL_POINTER,
        "Module Destroy function is null pointer")

    return g_hksHalDevicePtr->HuksHdiModuleDestroy();
}

ENABLE_CFI(int32_t HuksAccessRefresh(void))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiRefresh, HKS_ERROR_NULL_POINTER,
        "Refresh function is null pointer")

    return g_hksHalDevicePtr->HuksHdiRefresh();
}

ENABLE_CFI(int32_t HuksAccessGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGenerateKey, HKS_ERROR_NULL_POINTER,
        "GenerateKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSetIn, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiGenerateKey(keyAlias, paramSetInNew, keyIn, keyOut);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiImportKey, HKS_ERROR_NULL_POINTER,
        "ImportKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiImportKey(keyAlias, key, paramSetInNew, keyOut);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiImportWrappedKey, HKS_ERROR_NULL_POINTER,
        "ImportWrappedKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSetInNew, keyOut);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiExportPublicKey, HKS_ERROR_NULL_POINTER,
        "ExportPublicKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiExportPublicKey(key, paramSetInNew, keyOut);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiInit, HKS_ERROR_NULL_POINTER,
        "Init function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiInit(key, paramSetInNew, handle, token);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiUpdate, HKS_ERROR_NULL_POINTER,
        "Update function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiUpdate(handle, paramSetInNew, inData, outData);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiFinish, HKS_ERROR_NULL_POINTER,
        "Finish function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiFinish(handle, paramSetInNew, inData, outData);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiAbort, HKS_ERROR_NULL_POINTER,
        "Abort function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiAbort(handle, paramSetInNew);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGetKeyProperties, HKS_ERROR_NULL_POINTER,
        "GetKeyProperties function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiGetKeyProperties(paramSetInNew, key);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessGetAbility(int funcType))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGetAbility, HKS_ERROR_NULL_POINTER,
        "GetAbility function is null pointer")

    return g_hksHalDevicePtr->HuksHdiGetAbility(funcType);
}

ENABLE_CFI(int32_t HuksAccessGetHardwareInfo(void))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGetHardwareInfo, HKS_ERROR_NULL_POINTER,
        "GetHardwareInfo function is null pointer")

    return g_hksHalDevicePtr->HuksHdiGetHardwareInfo();
}

ENABLE_CFI(int32_t HuksAccessSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiSign, HKS_ERROR_NULL_POINTER,
        "Sign function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiSign(key, paramSetInNew, srcData, signature);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiVerify, HKS_ERROR_NULL_POINTER,
        "Verify function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiVerify(key, paramSetInNew, srcData, signature);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiEncrypt, HKS_ERROR_NULL_POINTER,
        "Encrypt function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiEncrypt(key, paramSetInNew, plainText, cipherText);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiDecrypt, HKS_ERROR_NULL_POINTER,
        "Decrypt function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiDecrypt(key, paramSetInNew, cipherText, plainText);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiAgreeKey, HKS_ERROR_NULL_POINTER,
        "AgreeKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiAgreeKey(paramSetInNew, privateKey, peerPublicKey, agreedKey);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiDeriveKey, HKS_ERROR_NULL_POINTER,
        "DeriveKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiDeriveKey(paramSetInNew, kdfKey, derivedKey);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiMac, HKS_ERROR_NULL_POINTER,
        "Mac function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiMac(key, paramSetInNew, srcData, mac);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}

ENABLE_CFI(int32_t HuksAccessGetErrorInfo(struct HksBlob *errorInfo))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGetErrorInfo, HKS_ERROR_NULL_POINTER,
        "GetErrorInfo function is null pointer")

    return g_hksHalDevicePtr->HuksHdiGetErrorInfo(errorInfo);
}

ENABLE_CFI(int32_t HuksAccessGetStatInfo(struct HksBlob *statInfo))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGetStatInfo, HKS_ERROR_NULL_POINTER,
        "GetErrorInfo function is null pointer")

    return g_hksHalDevicePtr->HuksHdiGetStatInfo(statInfo);
}

#ifdef HKS_ENABLE_UPGRADE_KEY
ENABLE_CFI(int32_t HuksAccessUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiUpgradeKey, HKS_ERROR_NULL_POINTER,
        "Change key owner function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiUpgradeKey(oldKey, paramSetInNew, newKey);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}
#endif

#ifdef _STORAGE_LITE_
ENABLE_CFI(int32_t HuksAccessCalcHeaderMac(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiCalcMacHeader, HKS_ERROR_NULL_POINTER,
        "CalcMacHeader function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiCalcMacHeader(paramSetInNew, salt, srcData, mac);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
ENABLE_CFI(int32_t HuksAccessAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiAttestKey, HKS_ERROR_NULL_POINTER,
        "AttestKey function is null pointer")
    struct HksParamSet *paramSetInNew = NULL;
    int32_t ret = HandleKeyClassTag(paramSet, &paramSetInNew);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HandleKeyClassTag fail, ret = %" LOG_PUBLIC "d", ret)
    ret = g_hksHalDevicePtr->HuksHdiAttestKey(key, paramSetInNew, certChain);
    HksFreeParamSet(&paramSetInNew);
    return ret;
}
#endif

#endif /* _CUT_AUTHENTICATE_ */

ENABLE_CFI(int32_t HuksAccessGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random))
{
    HKS_IF_NOT_SUCC_RETURN(HksCreateHuksHdiDevice(&g_hksHalDevicePtr), HKS_ERROR_NULL_POINTER)

    HKS_IF_NULL_LOGE_RETURN(g_hksHalDevicePtr->HuksHdiGenerateRandom, HKS_ERROR_NULL_POINTER,
        "GenerateRandom function is null pointer")

    return g_hksHalDevicePtr->HuksHdiGenerateRandom(paramSet, random);
}
