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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "huks_hdi_interfaces.h"

#include "huks_core_hal.h"

#include "hks_log.h"
#include "hks_mem.h"

static struct HksHalDevice *g_hksHalDevicePtr = NULL;

#ifndef _CUT_AUTHENTICATE_
int32_t HuksHdiModuleInit(void)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->ModuleInit == NULL) {
        HKS_LOG_E("Module Init function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->ModuleInit();
}

int32_t HuksHdiRefresh(void)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Refresh == NULL) {
        HKS_LOG_E("Refresh function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Refresh();
}

int32_t HuksHdiGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->GenerateKey == NULL) {
        HKS_LOG_E("GenerateKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->GenerateKey(keyAlias, paramSetIn, keyIn, keyOut);
}

int32_t HuksHdiImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->ImportKey == NULL) {
        HKS_LOG_E("ImportKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->ImportKey(keyAlias, key, paramSet, keyOut);
}

int32_t HuksHdiImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->ImportWrappedKey == NULL) {
        HKS_LOG_E("ImportWrappedKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->ImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

int32_t HuksHdiExportPublicKey(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->ExportPublicKey == NULL) {
        HKS_LOG_E("ExportPublicKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->ExportPublicKey(key, paramSet, keyOut);
}

int32_t HuksHdiInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Init == NULL) {
        HKS_LOG_E("Init function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Init(key, paramSet, handle);
}

int32_t HuksHdiUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Update == NULL) {
        HKS_LOG_E("Update function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Update(handle, paramSet, inData, outData);
}

int32_t HuksHdiFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Finish == NULL) {
        HKS_LOG_E("Finish function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Finish(handle, paramSet, inData, outData);
}

int32_t HuksHdiAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Abort == NULL) {
        HKS_LOG_E("Abort function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Abort(handle, paramSet);
}

int32_t HuksHdiGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->GetKeyProperties == NULL) {
        HKS_LOG_E("GetKeyProperties function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->GetKeyProperties(paramSet, key);
}

int32_t HuksHdiGetAbility(int funcType)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->GetAbility == NULL) {
        HKS_LOG_E("GetAbility function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->GetAbility(funcType);
}

int32_t HuksHdiGetHardwareInfo(void)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->GetHardwareInfo == NULL) {
        HKS_LOG_E("GetHardwareInfo function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->GetHardwareInfo();
}

int32_t HuksHdiProcessInit(uint32_t msgId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    uint64_t *operationHandle)
{
    (void)msgId;
    (void)key;
    (void)paramSet;
    (void)operationHandle;
    return 0;
}

int32_t HuksHdiProcessMultiUpdate(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    (void)msgId;
    (void)operationHandle;
    (void)inData;
    (void)outData;
    return 0;
}

int32_t HuksHdiProcessFinal(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    (void)msgId;
    (void)operationHandle;
    (void)inData;
    (void)outData;
    return 0;
}

int32_t HuksHdiSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Sign == NULL) {
        HKS_LOG_E("Sign function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Sign(key, paramSet, srcData, signature);
}

int32_t HuksHdiVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Verify == NULL) {
        HKS_LOG_E("Verify function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Verify(key, paramSet, srcData, signature);
}

int32_t HuksHdiEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Encrypt == NULL) {
        HKS_LOG_E("Encrypt function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Encrypt(key, paramSet, plainText, cipherText);
}

int32_t HuksHdiDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Decrypt == NULL) {
        HKS_LOG_E("Decrypt function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Decrypt(key, paramSet, cipherText, plainText);
}

int32_t HuksHdiAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->AgreeKey == NULL) {
        HKS_LOG_E("AgreeKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->AgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
}

int32_t HuksHdiDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->DeriveKey == NULL) {
        HKS_LOG_E("DeriveKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->DeriveKey(paramSet, kdfKey, derivedKey);
}

int32_t HuksHdiMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->Mac == NULL) {
        HKS_LOG_E("Mac function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->Mac(key, paramSet, srcData, mac);
}

#ifdef _STORAGE_LITE_
int32_t HuksHdiCalcHeaderMac(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->CalcMacHeader == NULL) {
        HKS_LOG_E("CalcMacHeader function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->CalcMacHeader(paramSet, salt, srcData, mac);
}
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
int32_t HuksHdiUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo, struct HksBlob *keyOut)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->UpgradeKeyInfo == NULL) {
        HKS_LOG_E("UpgradeKeyInfo function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->UpgradeKeyInfo(keyAlias, keyInfo, keyOut);
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
int32_t HuksHdiAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *certChain)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->AttestKey == NULL) {
        HKS_LOG_E("AttestKey function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->AttestKey(key, paramSet, certChain);
}
#endif

#endif /* _CUT_AUTHENTICATE_ */

int32_t HuksHdiGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    if (HksCreateHuksHdiDevice(&g_hksHalDevicePtr) != HKS_SUCCESS) {
        return HKS_ERROR_NULL_POINTER;
    }
    if (g_hksHalDevicePtr->GenerateRandom == NULL) {
        HKS_LOG_E("GenerateRandom function is null pointer");
        return HKS_ERROR_NULL_POINTER;
    }
    return g_hksHalDevicePtr->GenerateRandom(paramSet, random);
}
