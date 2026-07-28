/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UKEY_SERVICE_ADAPTER_H
#define HKS_UKEY_SERVICE_ADAPTER_H

#include "hks_type.h"
#include "hks_plugin_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet);
int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet);
int32_t HksIpcQueryAbilityInfoAdapter(const struct HksProcessInfo *processInfo, struct HksBlob *resourceId,
    struct HksAbilityInfo *abilityInfo);
int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo);
int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo);
int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet, struct HksExternalErrorInfo **errInfo);
int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet, struct HksExternalErrorInfo **errInfo);
int32_t HksIpcImportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksExtCertInfo *certInfo, const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo);
int32_t HksIpcAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSet, struct HksExtAuthPinOutParam *authOutParam,
    struct HksExternalErrorInfo **errInfo);
int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus,
    struct HksExternalErrorInfo **errInfo);
int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    struct HksExternalErrorInfo **errInfo);
int32_t HksIpcServiceOnSetOrGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksExtPropertyOperationInfo *propertyInfo, const struct HksParamSet *paramSet,
    const uint8_t *remoteObject);
int32_t HksIpcServiceOnGetResourceIdAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *providerName, const struct HksParamSet *paramSet, struct HksBlob *resourceId,
    struct HksExternalErrorInfo **errInfo);

int32_t HksServiceOnUkeyGenerateKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet);
int32_t HksServiceOnUkeyInitSession(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *handle);
int32_t HksServiceOnUkeyUpdateSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData);
int32_t HksServiceOnUkeyFinishSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData);
int32_t HksServiceOnUkeyAbortSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet);
int32_t HksServiceOnUkeyImportWrappedKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);
int32_t HksServiceOnUkeyExportPublicKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key);

#ifdef __cplusplus
}
#endif

#endif // HKS_UKEY_SERVICE_ADAPTER_H
