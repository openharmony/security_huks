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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#include "hks_error_code.h"
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_ukey_client_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include "hks_type.h"
#include "hks_base_check.h"
#include "hks_client_check.h"

#ifdef L2_STANDARD
#include "hks_ha_event_report.h"
#include "hks_ukey_three_stage_adapter.h"
#include "hks_ukey_service_provider_adapter.h"
#endif

#include "securec.h"

int32_t HksServiceRegisterProvider(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSetIn)
{
    /* Only meaningful under L2_STANDARD; LiteOS/non-standard returns not supported */
#ifdef L2_STANDARD
    return HksIpcProviderRegAdapter(processInfo, name, paramSetIn);
#else
    (void)processInfo;
    (void)name;
    (void)paramSetIn;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceUnregisterProvider(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    return HksIpcProviderUnregAdapter(processInfo, name, paramSetIn);
#else
    (void)processInfo;
    (void)name;
    (void)paramSetIn;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceExportProviderCertificates(const struct HksProcessInfo *processInfo,
    const struct HksBlob *providerName, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
#ifdef L2_STANDARD
    return HksIpcExportProvCertsAdapter(processInfo, providerName, paramSetIn, certSet);
#else
    (void)processInfo;
    (void)providerName;
    (void)paramSetIn;
    (void)certSet;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceExportCertificate(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
#ifdef L2_STANDARD
    return HksIpcExportCertAdapter(processInfo, index, paramSetIn, certSet);
#else
    (void)processInfo;
    (void)index;
    (void)paramSetIn;
    (void)certSet;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceAuthUkeyPin(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, int32_t *outStatus, uint32_t *retryCount)
{
#ifdef L2_STANDARD
    return HksIpcAuthUkeyPinAdapter(processInfo, index, paramSetIn, outStatus, retryCount);
#else
    (void)processInfo;
    (void)index;
    (void)paramSetIn;
    (void)outStatus;
    (void)retryCount;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceOpenRemoteHandle(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    struct HksBlob remoteHandle = {0, NULL};
    return HksIpcCreateRemKeyHandleAdapter(processInfo, index, paramSetIn, &remoteHandle);
#else
    (void)processInfo;
    (void)index;
    (void)paramSetIn;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceGetUkeyPinAuthState(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, int32_t *status)
{
#ifdef L2_STANDARD
    return HksIpcGetUkeyPinAuthStateAdapter(processInfo, index, paramSetIn, status);
#else
    (void)processInfo;
    (void)index;
    (void)paramSetIn;
    (void)status;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceCloseRemoteHandle(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *paramSetIn)
{
#ifdef L2_STANDARD
    return HksIpcCloseRemKeyHandleAdapter(processInfo, index, paramSetIn);
#else
    (void)processInfo;
    (void)index;
    (void)paramSetIn;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceClearPinAuthState(const struct HksProcessInfo *processInfo, const struct HksBlob *index)
{
#ifdef L2_STANDARD
    return HksIpcClearPinStatusAdapter(processInfo, index);
#else
    (void)processInfo;
    (void)index;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}

int32_t HksServiceGetRemoteProperty(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksBlob *propertyId, const struct HksParamSet *paramSetIn, struct HksParamSet **propertySetOut)
{
#ifdef L2_STANDARD
    return HksIpcServiceOnGetRemotePropertyAdapter(processInfo, resourceId, propertyId, paramSetIn, NULL);
#else
    (void)processInfo;
    (void)resourceId;
    (void)propertyId;
    (void)paramSetIn;
    (void)propertySetOut;
    return HKS_ERROR_API_NOT_SUPPORTED;
#endif
}