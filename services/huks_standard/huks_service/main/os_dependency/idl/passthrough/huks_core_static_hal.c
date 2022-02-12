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

#include "hks_crypto_hal.h"
#include "huks_hal_interfaces.h"
#include "hks_core_interfaces.h"
#include "hks_type_inner.h"
#include "hks_mem.h"

struct HksHalDevice *g_hksHalDevicePtr = NULL;

static int32_t CheckPtr(void *ptr)
{
    if (ptr == NULL) {
        HKS_LOG_E("CheckPtr failed");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

#ifndef _CUT_AUTHENTICATE_
int32_t HksHalModuleInit(void)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->ModuleInit) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->ModuleInit();
    }
    return HKS_FAILURE;
}

int32_t HksHalRefresh(void)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->Refresh) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->Refresh();
    }
    return HKS_FAILURE;
}

int32_t HksHalGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->GenerateKey) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->GenerateKey(keyAlias, paramSetIn, keyIn, keyOut);
    }
    return HKS_FAILURE;
}

int32_t HksHalImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->ImportKey) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->ImportKey(keyAlias, key, paramSet, keyOut);
    }
    return HKS_FAILURE;
}

int32_t HksHalImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->ImportWrappedKey) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->ImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
    }
    return HKS_FAILURE;
}

int32_t HksHalExportPublicKey(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->ExportPublicKey) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->ExportPublicKey(key, paramSet, keyOut);
    }
    return HKS_FAILURE;
}

int32_t HksHalInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->Init) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->Init(key, paramSet, handle);
    }
    return HKS_FAILURE;
}

int32_t HksHalUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->Update) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->Update(handle, paramSet, inData, outData);
    }
    return HKS_FAILURE;
}

int32_t HksHalFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->Finish) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->Finish(handle, paramSet, inData, outData);
    }
    return HKS_FAILURE;
}

int32_t HksHalAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->Abort) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->Abort(handle, paramSet);
    }
    return HKS_FAILURE;
}

int32_t HksHalGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->GetKeyProperties) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->GetKeyProperties(paramSet, key);
    }
    return HKS_FAILURE;
}

int32_t HksHalAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->AttestKey) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->AttestKey(key, paramSet, certChain);
    }
    return HKS_FAILURE;
}

int32_t HksHalGetAbility(int funcType)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->GetAbility) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->GetAbility(funcType);
    }
    return HKS_FAILURE;
}

int32_t HksHalGetHardwareInfo(void)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->GetHardwareInfo) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->GetHardwareInfo();
    }
    return HKS_FAILURE;
}

int32_t HksHalProcessInit(uint32_t msgId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    uint64_t *operationHandle)
{
    (void)msgId;
    (void)key;
    (void)paramSet;
    (void)operationHandle;
    return 0;
}

int32_t HksHalProcessMultiUpdate(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    (void)msgId;
    (void)operationHandle;
    (void)inData;
    (void)outData;
    return 0;
}

int32_t HksHalProcessFinal(uint32_t msgId, uint64_t operationHandle, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    (void)msgId;
    (void)operationHandle;
    (void)inData;
    (void)outData;
    return 0;
}

#ifdef _STORAGE_LITE_
int32_t HksHalCalcHeaderMac(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->CalcMacHeader) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->CalcMacHeader(paramSet, salt, srcData, mac);
    }
    return HKS_FAILURE;
}
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
int32_t HksHalUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo, struct HksBlob *keyOut)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->UpgradeKeyInfo) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->UpgradeKeyInfo(keyAlias, keyInfo, keyOut);
    }
    return HKS_FAILURE;
}
#endif

#ifdef HKS_SUPPORT_API_ATTEST_KEY
int32_t HksHalAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *certChain)
{
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif

#endif /* _CUT_AUTHENTICATE_ */

int32_t HksHalGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    if (CheckPtr((void *)g_hksHalDevicePtr->GenerateRandom) == HKS_SUCCESS) {
        return g_hksHalDevicePtr->GenerateRandom(paramSet, random);
    }
    return HKS_FAILURE;
}

int32_t HksCreateHksHalDevice(void)
{
    if (g_hksHalDevicePtr != NULL) {
        return HKS_SUCCESS;
    }

    g_hksHalDevicePtr = (struct HksHalDevice *)HksCreateCoreIfDevicePtr();
    if (g_hksHalDevicePtr == NULL)  {
        HKS_LOG_E("g_hksHalDevicePtr is NULL!");
        return HKS_ERROR_NULL_POINTER;
    }

    return HKS_SUCCESS;
}

int32_t HksDestroyHksHalDevice(void)
{
    if (g_hksHalDevicePtr != NULL) {
        HksDestoryCoreIfDevicePtr();
        g_hksHalDevicePtr = NULL;
    }
    return HKS_SUCCESS;
}

