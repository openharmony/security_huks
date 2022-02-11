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

#include "hks_core_interfaces.h"
#include "hks_mem.h"
#include "hks_core_service.h"

struct HksCoreIfDevice *g_hksCoreIfDevicePtr = NULL;

int32_t HksCoreIfModuleInit(void)
{
    return HksCoreModuleInit();
}

int32_t HksCoreIfRefresh(void)
{
    return HksCoreRefresh();
}

int32_t HksCoreIfGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    return HksCoreGenerateKey(keyAlias, paramSet, keyIn, keyOut);
}

int32_t HksCoreIfImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    return HksCoreImportKey(keyAlias, key, paramSet, keyOut);
}

int32_t HksCoreIfImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    return HksCoreImportWrappedKey(wrappingKeyAlias, key, wrappedKeyData, paramSet, keyOut);
}

int32_t HksCoreIfExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    return HksCoreExportPublicKey(key, paramSet, keyOut);
}

int32_t HksCoreIfInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle)
{
    return HksCoreInit(key, paramSet, handle);
}

int32_t HksCoreIfUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    return HksCoreUpdate(handle, paramSet, inData, outData);
}

int32_t HksCoreIfFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    return HksCoreFinish(handle, paramSet, inData, outData);
}

int32_t HksCoreIfAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    return HksCoreAbort(handle, paramSet);
}

int32_t HksCoreIfGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    return HksCoreGetKeyProperties(paramSet, key);
}

int32_t HksCoreIfAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain)
{
    return HksCoreAttestKey(key, paramSet, certChain);
}

int32_t HksCoreIfGetAbility(int funcType)
{
    return HksCoreGetAbility(funcType);
}

int32_t HksCoreIfGetHardwareInfo(void)
{
    return HksCoreGetHardwareInfo();
}

int32_t HksCoreIfGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    return HksCoreGenerateRandom(paramSet, random);
}

#ifdef _STORAGE_LITE_
int32_t HksCoreIfCalcMacHeader(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    return HksCoreCalcMacHeader(paramSet, salt, srcData, mac);
}
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
int32_t HksCoreIfUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo, struct HksBlob *keyOut)
{
    return HksCoreUpgradeKeyInfo(keyAlias, keyInfo, keyOut);
}
#endif

struct HksCoreIfDevice *HksCreateCoreIfDevicePtr(void)
{
    g_hksCoreIfDevicePtr = (struct HksCoreIfDevice *)HksMalloc(sizeof(struct HksCoreIfDevice));
    if (g_hksCoreIfDevicePtr == NULL) {
        HKS_LOG_E("HksCreateCoreIfDevicePtr malloc g_hksCoreIfDevicePtr failed.");
        return g_hksCoreIfDevicePtr;
    }
    (void)memset_s(g_hksCoreIfDevicePtr, sizeof(struct HksCoreIfDevice), 0, sizeof(struct HksCoreIfDevice));

#ifndef _CUT_AUTHENTICATE_
    g_hksCoreIfDevicePtr->ModuleInit       = HksCoreIfModuleInit;
    g_hksCoreIfDevicePtr->Refresh          = HksCoreIfRefresh;
    g_hksCoreIfDevicePtr->GenerateKey      = HksCoreIfGenerateKey;
    g_hksCoreIfDevicePtr->ImportKey        = HksCoreIfImportKey;
    g_hksCoreIfDevicePtr->ImportWrappedKey = HksCoreIfImportWrappedKey;
    g_hksCoreIfDevicePtr->ExportPublicKey  = HksCoreIfExportPublicKey;
    g_hksCoreIfDevicePtr->Init             = HksCoreIfInit;
    g_hksCoreIfDevicePtr->Update           = HksCoreIfUpdate;
    g_hksCoreIfDevicePtr->Finish           = HksCoreIfFinish;
    g_hksCoreIfDevicePtr->Abort            = HksCoreIfAbort;
    g_hksCoreIfDevicePtr->GetKeyProperties = HksCoreIfGetKeyProperties;
    g_hksCoreIfDevicePtr->AttestKey        = HksCoreIfAttestKey;
    g_hksCoreIfDevicePtr->GetAbility       = HksCoreIfGetAbility;
    g_hksCoreIfDevicePtr->GetHardwareInfo  = HksCoreIfGetHardwareInfo;

#ifdef _STORAGE_LITE_
    g_hksCoreIfDevicePtr->CalcMacHeader    = HksCoreIfCalcMacHeader;
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
    g_hksCoreIfDevicePtr->UpgradeKeyInfo   = HksCoreIfUpgradeKeyInfo;
#endif
#endif /* _CUT_AUTHENTICATE_ */

    g_hksCoreIfDevicePtr->GenerateRandom   = HksCoreGenerateRandom;

    return g_hksCoreIfDevicePtr;
}

void HksDestoryCoreIfDevicePtr(void)
{
    HksMutexClose(HksCoreGetHuksMutex());
    if (g_hksCoreIfDevicePtr != NULL) {
        free(g_hksCoreIfDevicePtr);
        g_hksCoreIfDevicePtr = NULL;
    }
}
