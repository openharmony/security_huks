/*
 * Copyright (c) 2020-2025 Huawei Device Co., Ltd.
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

#include "hks_client_ipc.h"
#include "hks_ukey_client_service.h"
#include "hks_get_process_info.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"

static int32_t GetProcessInfo(const struct HksParamSet *paramSet, char **processName, char **userId)
{
    (void)paramSet;
#ifdef HKS_ENABLE_LITE_HAP
    struct HksParam *bundleNameParam = NULL;
    if (paramSet != NULL && HksGetParam(paramSet, HKS_TAG_BUNDLE_NAME, &bundleNameParam) == HKS_SUCCESS) {
        // the end of bundleNameParam->blob.data is \0 and it's considered in blob.size
        *processName = (char *)bundleNameParam->blob.data;
    } else {
#endif
        HKS_IF_NOT_SUCC_LOGE_RETURN(HksGetProcessName(processName), HKS_ERROR_INTERNAL_ERROR, "get process name failed")
#ifdef HKS_ENABLE_LITE_HAP
    }
#endif
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksGetUserId(userId), HKS_ERROR_INTERNAL_ERROR, "get user id failed")
    return HKS_SUCCESS;
}

int32_t HksClientRegisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceRegisterProvider(&processInfo, name, paramSetIn);
}

int32_t HksClientUnregisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceUnregisterProvider(&processInfo, name, paramSetIn);
}

int32_t HksClientExportProviderCertificates(const struct HksBlob *providerName,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceExportProviderCertificates(&processInfo, providerName, paramSetIn, certSet);
}

int32_t HksClientExportCertificate(const struct HksBlob *index,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceExportCertificate(&processInfo, index, paramSetIn, certSet);
}

int32_t HksClientOpenRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceOpenRemoteHandle(&processInfo, resourceId, paramSetIn);
}


int32_t HksClientAuthUkeyPin(const struct HksBlob *index, const struct HksParamSet *paramSetIn, uint32_t *retryCount)
{
    char *processName = NULL;
    char *userId = NULL;
    int32_t outStatus;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceAuthUkeyPin(&processInfo, index, paramSetIn, &outStatus, retryCount);
}

int32_t HksClientGetUkeyPinAuthState(const struct HksBlob *index, const struct HksParamSet *paramSetIn, int32_t *status)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceGetUkeyPinAuthState(&processInfo, index, paramSetIn, status);
}

int32_t HksClientCloseRemoteHandle(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceCloseRemoteHandle(&processInfo, resourceId, paramSetIn);
}

int32_t HksClientClearPinAuthState(const struct HksBlob *index)
{
    struct HksProcessInfo processInfo = {
        { 0, NULL }, // userId
        { 0, NULL }, // processName
        0,
        0,
        0,
        0
    };
    return HksServiceClearPinAuthState(&processInfo, index);
}

int32_t HksClientGetRemoteProperty(const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSetIn, struct HksParamSet **propertySetOut)
{
    char *processName = NULL;
    char *userId = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetProcessInfo(paramSetIn, &processName, &userId), HKS_ERROR_INTERNAL_ERROR,
        "get process info failed")

    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0,
        0
    };
    return HksServiceGetRemoteProperty(&processInfo, resourceId, propertyId, paramSetIn, propertySetOut);
}
