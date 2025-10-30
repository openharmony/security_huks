/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_IPC_SERVICE_PROVIDER_ADAPTER_H
#define HKS_IPC_SERVICE_PROVIDER_ADAPTER_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// 注册注销
int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name,
    const struct HksParamSet *paramSet);
int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name,
    const struct HksParamSet *paramSet);

int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet);

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus, uint32_t *retryCount);

int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus);

int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index);

int32_t HksIpcServiceOnGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSet, const uint8_t *remoteObject);

#ifdef __cplusplus
}
#endif

#endif // HKS_IPC_SERVICE_PROVIDER_ADAPTER_H