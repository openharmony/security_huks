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

#ifndef HKS_CLIENT_SERVICE_H
#define HKS_CLIENT_SERVICE_H


#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#include "hks_type_inner.h"

struct HksIpcData {
    const struct HksBlob *srcData;
    const uint8_t *context;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksServiceInitialize(void);

int32_t HksServiceRefreshKeyInfo(const struct HksBlob *processName);

int32_t HksServiceRegisterProvider(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSetIn);

int32_t HksServiceUnregisterProvider(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSetIn);

int32_t HksServiceExportProviderCertificates(const struct HksProcessInfo *processInfo,
    const struct HksBlob *providerName, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet);

int32_t HksServiceExportCertificate(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn,
    struct HksExtCertInfoSet *certSet);

int32_t HksServiceAuthUkeyPin(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, int32_t *outStatus, uint32_t *retryCount);

int32_t HksServiceOpenRemoteHandle(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn);

int32_t HksServiceGetUkeyPinAuthState(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, int32_t *status);

int32_t HksServiceCloseRemoteHandle(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn);

int32_t HksServiceClearPinAuthState(const struct HksProcessInfo *processInfo, const struct HksBlob *index);

int32_t HksServiceGetRemoteProperty(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksBlob *propertyId, const struct HksParamSet *paramSetIn, struct HksParamSet **propertySetOut);

#ifdef __cplusplus
}
#endif

#endif
