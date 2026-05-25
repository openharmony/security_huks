/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "hks_ipc_service.h"
#include "hks_error_code.h"
#include "hks_type.h"

#include "hks_ipc_serialization.h"
#include <dlfcn.h>
#include <securec.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "hks_common_check.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_base_check.h" // for HksAttestIsAnonymous
#include "hks_client_check.h"
#include "hks_client_service_dcm.h"
#include "hks_client_service.h"
#include "hks_client_service_common.h"
#include "hks_cmd_id.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_permission_check.h"
#include "hks_plugin_adapter.h"
#include "hks_response.h"
#include "hks_service_ipc_serialization.h"
#include "hks_template.h"
#include "hks_util.h"
#include "hks_report_ukey_event.h"
#include "hks_report_common.h"
#include "hks_external_error_info.h"

#ifdef L2_STANDARD
#include "hks_se_api_wrap.h"
#endif

#define MAX_KEY_SIZE         2048

#define RET_NUM    2
#define UKEY_PERMISSION_REGISTER "ohos.permission.CRYPTO_EXTENSION_REGISTER"

#ifdef HKS_SUPPORT_ACCESS_TOKEN
static enum HksTag g_idList[] = {
    HKS_TAG_ATTESTATION_ID_BRAND,
    HKS_TAG_ATTESTATION_ID_DEVICE,
    HKS_TAG_ATTESTATION_ID_PRODUCT,
    HKS_TAG_ATTESTATION_ID_SERIAL,
    HKS_TAG_ATTESTATION_ID_IMEI,
    HKS_TAG_ATTESTATION_ID_MEID,
    HKS_TAG_ATTESTATION_ID_MANUFACTURER,
    HKS_TAG_ATTESTATION_ID_MODEL,
    HKS_TAG_ATTESTATION_ID_SOCID,
    HKS_TAG_ATTESTATION_ID_UDID,
};
#endif

void HksIpcServiceRegisterProvider(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob name = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &name, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceRegisterProviderUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckUkeyPermission(UKEY_PERMISSION_REGISTER);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckUkeyPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcProviderRegAdapter(&processInfo, &name, paramSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksIpcProviderRegAdapter fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER, .operation = HKS_UKEY_REPORT_REGISTER,
        .providerName = name };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceUnregisterProvider(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob name = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &name, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceUnregisterProviderUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckUkeyPermission(UKEY_PERMISSION_REGISTER);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckUkeyPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcProviderUnregAdapter(&processInfo, &name, paramSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksIpcProviderUnregAdapter fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_REGISTER_PROVIDER, .operation = HKS_UKEY_REPORT_UNREGISTER,
        .providerName = name };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceQueryAbilityInfo(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob resourceId = { 0, NULL };
    struct HksAbilityInfo abilityInfo;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksBlob outBlob = { 0, NULL };
    int32_t ret;

    do {
        ret = HksBlob3Unpack(srcData, &resourceId, &abilityInfo.bundleName, &abilityInfo.abilityName);
        HKS_IF_NOT_SUCC_BREAK(ret, "HksIpcServiceQueryAbilityInfo Ipc fail")

        ret = HksGetProcessInfoForIPC(NULL, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcQueryAbilityInfoAdapter(&processInfo, &resourceId, &abilityInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcQueryAbilityInfoAdapter fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksAllocInBlobWithThreeBlobs(&outBlob, &resourceId, &abilityInfo.bundleName, &abilityInfo.abilityName);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "alloc outBlob fail")

        ret = HksBlob3Pack(&resourceId, &abilityInfo.bundleName, &abilityInfo.abilityName, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Huks service pack fail")
    } while (0);

    HksSendResponse(context, ret, &outBlob);
    
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(outBlob);

#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceAuthUkeyPin(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob index = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExtAuthPinOutParam authOutParam = {0, 0};
    struct HksBlob outBlob = { 0, NULL };
    struct HksExternalErrorInfo *errInfo = NULL;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &index, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AuthUkeyPin: unpack fail");
    
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AuthUkeyPin: get process info fail ret=%" LOG_PUBLIC "d", ret);
    
        ret = CheckUkeyAuthPinType();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AuthUkeyPin: CheckUkeyAuthPinType fail ret=%" LOG_PUBLIC "d", ret);

        ret = HksIpcAuthUkeyPinAdapter(&processInfo, &index, paramSet, &authOutParam, &errInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksIpcAuthUkeyPinAdapter fail, ret = %" LOG_PUBLIC "d", ret);
            HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
            HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
            HksFreeExternalErrorInfo(errInfo);
        }

        ret = PackAuthPinReply(&outBlob, ret, authOutParam.outStatus, authOutParam.retryCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PackAuthPinReply fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, (ret == HKS_ERROR_BAD_STATE || ret == HKS_ERROR_MALLOC_FAIL) ? ret : HKS_SUCCESS,
        (outBlob.data != NULL && outBlob.size == (sizeof(int32_t) * RET_NUM + sizeof(uint32_t))) ? &outBlob : NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_AUTH_PIN, .resourceId = index };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(outBlob);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceGetUkeyPinAuthState(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob index = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t status = 0;
    struct HksBlob outBlob = { 0, NULL };
    struct HksExternalErrorInfo *errInfo = NULL;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &index, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetUkeyPinAuthState: unpack fail");

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetUkeyPinAuthState: get process info fail ret=%" LOG_PUBLIC "d", ret);

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetUkeyPinAuthState: permission fail ret=%" LOG_PUBLIC "d", ret);

        ret = HksIpcGetUkeyPinAuthStateAdapter(&processInfo, &index, paramSet, &status, &errInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("GetUkeyPinAuthState: adapter ret=%" LOG_PUBLIC "d", ret);
            HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
            HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
            HksFreeExternalErrorInfo(errInfo);
            break;
        }

        outBlob.size = (uint32_t)sizeof(int32_t);
        outBlob.data = (uint8_t *)(&status);
    } while (0);

    HksSendResponse(context, ret,
        (outBlob.data != NULL && outBlob.size == (uint32_t)sizeof(int32_t)) ? &outBlob : NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_GET_AUTH_PIN_STATE, .state = status, .resourceId = index };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceClearPinAuthState(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    int32_t ret;
    struct HksBlob index = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;

    do {
        ret  = HksClearPinAuthStateUnpack(srcData, &index);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceClearPinAuthStateUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(NULL, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksIpcClearPinStatusAdapter(&processInfo, &index, &errInfo);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS)
        HKS_LOG_E("HksIpcClearPinStatusAdapter ret = %" LOG_PUBLIC "d", ret);
        HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
        HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
        HksFreeExternalErrorInfo(errInfo);
    } while (0);

    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_CLEAR_PIN_STATE,
        .resourceId = index, .detailErrcode = ret };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, NULL, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceOpenRemoteHandle(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob resourceId = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret  = HksUKeyGeneralUnpack(srcData, &resourceId, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceOpenRemoteHandleUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcCreateRemKeyHandleAdapter(&processInfo, &resourceId, paramSet, &errInfo);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS)
        HKS_LOG_E("HksIpcCreateRemKeyHandleAdapter fail, ret = %" LOG_PUBLIC "d", ret);
        HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
        HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
        HksFreeExternalErrorInfo(errInfo);
    } while (0);

    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        .operation = HKS_UKEY_REPORT_OPEN_HANDLE, .resourceId = resourceId };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);
    
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceCloseRemoteHandle(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob resourceId = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret  = HksUKeyGeneralUnpack(srcData, &resourceId, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceCloseRemoteHandleUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcCloseRemKeyHandleAdapter(&processInfo, &resourceId, paramSet, &errInfo);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS)
        HKS_LOG_E("HksIpcCloseRemKeyHandleAdapter fail, ret = %" LOG_PUBLIC "d", ret);
        HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
        HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
        HksFreeExternalErrorInfo(errInfo);
    } while (0);

    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        .operation = HKS_UKEY_REPORT_CLOSE_HANDLE, .resourceId = resourceId };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceExportProviderCertificates(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob providerName = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksExtCertInfoSet certInfoSet = {0, NULL};
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    struct HksBlob certOut = { 0, NULL };
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &providerName, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceExportProviderCertificatesUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckUkeyCertCaller(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckUkeyCertCaller fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcExportProvCertsAdapter(&processInfo, &providerName, paramSet, &certInfoSet, &errInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksIpcExportProvCertsAdapter fail, ret = %" LOG_PUBLIC "d", ret);
            HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
            HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
            HksFreeExternalErrorInfo(errInfo);
            break;
        }

        ret = HksCertificatesPackFromService(&certInfoSet, &certOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificatesPackFromService fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS && certOut.size != 0 ? &certOut : NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT, .providerName = providerName };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    HksFreeExtCertSet(&certInfoSet);
    HKS_FREE_BLOB(certOut);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceExportCertificate(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob index = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksExtCertInfoSet certInfoSet = {0, NULL};
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    struct HksBlob certOut = { 0, NULL };
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpack(srcData, &index, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceExportCertificateUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckUkeyCertCaller(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckUkeyCertCaller fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcExportCertAdapter(&processInfo, &index, paramSet, &certInfoSet, &errInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksIpcExportCertAdapter fail, ret = %" LOG_PUBLIC "d", ret);
            HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
            HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
            HksFreeExternalErrorInfo(errInfo);
            break;
        }

        ret = HksCertificatesPackFromService(&certInfoSet, &certOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificatesPackFromService fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS && certOut.size != 0 ? &certOut : NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_EXPORT_CERT, .resourceId = index };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    HksFreeExtCertSet(&certInfoSet);
    HKS_FREE_BLOB(certOut);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceImportCertificate(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    struct HksBlob index = { 0, NULL };
    struct HksExtCertInfo certInfo = {0};
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    int32_t ret;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    do {
        ret = HksUKeyGeneralUnpackWithCertInfo(srcData, &index, &certInfo, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceImportCertificateUnpack Ipc fail")
        
        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)
        
        ret = CheckUkeyCertCaller(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckUkeyCertCaller fail, ret = %" LOG_PUBLIC "d", ret)
        
        ret = HksIpcImportCertAdapter(&processInfo, &index, &certInfo, paramSet, &errInfo);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS)
        HKS_LOG_E("HksIpcImportCertAdapter fail, ret = %" LOG_PUBLIC "d", ret);
        HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
        HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
        HksFreeExternalErrorInfo(errInfo);
    } while (0);
    HksSendResponse(context, ret, NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_IMPORT_CERT,
        .resourceId = index, .detailErrcode = ret };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

void HksIpcServiceSetOrGetRemoteProperty(const struct HksBlob *srcData,
    const uint8_t *context, const uint8_t *remoteObject)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    int32_t ret;
    enum HksExtPropertyOperation operation = HKS_EXT_PROPERTY_OPERATION_GET;
    struct HksBlob resourceId = { 0, NULL };
    struct HksBlob propertyId = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);

    do {
        ret = HksSetOrGetRemotePropertyUnpack(srcData, &operation, &resourceId, &propertyId, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSetOrGetRemotePropertyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        struct HksExtPropertyOperationInfo propertyInfo;
        propertyInfo.operation = operation;
        propertyInfo.resourceId = &resourceId;
        propertyInfo.propertyId = &propertyId;

        ret = HksIpcServiceOnSetOrGetRemotePropertyAdapter(&processInfo, &propertyInfo, paramSet, remoteObject);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceSetOrGetRemoteProperty fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    struct UKeyInfo ukeyInfo = { .eventId = (operation == HKS_EXT_PROPERTY_OPERATION_SET) ?
        HKS_EVENT_UKEY_SET_REMOTE_PROPERTY : HKS_EVENT_UKSY_GET_REMOTE_PROPERTY,
        .resourceId = resourceId, .propertyId = propertyId, .detailErrcode = ret };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret, .startTime = startTime };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
    (void)remoteObject;
#endif
}

void HksIpcServiceGetResourceId(const struct HksBlob *srcData, const uint8_t *context)
{
#ifdef HKS_UKEY_EXTENSION_CRYPTO
    int32_t ret;
    struct HksBlob providerName = { 0, NULL };
    struct HksBlob resourceId = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksExternalErrorInfo *errInfo = NULL;
    do {
        ret  = HksUKeyGeneralUnpack(srcData, &providerName, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksUKeyGeneralUnpack Ipc in HksIpcServiceGetResourceId fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksIpcServiceOnGetResourceIdAdapter(&processInfo, &providerName, paramSet, &resourceId, &errInfo);
        HKS_IF_TRUE_BREAK(ret == HKS_SUCCESS)
        HKS_LOG_E("HksIpcServiceOnGetResourceIdAdapter fail, ret = %" LOG_PUBLIC "d", ret);
        HKS_IF_NULL_LOGE_BREAK(errInfo, "errInfo is nullptr")
        HksAppendThreadExtErrMsg(errInfo->errVal, errInfo->errorDesc);
        HksFreeExternalErrorInfo(errInfo);
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS && resourceId.size != 0 ? &resourceId : NULL);

    struct UKeyInfo ukeyInfo = { .eventId = HKS_EVENT_UKEY_GET_RESOURCE_ID,
        .resourceId = resourceId, .providerName = providerName, .detailErrcode = ret };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret };
    ReportUKeyEvent(&ukeyInfo, __func__, &processInfo, paramSet, &ukeyCommon);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
#else
    (void)srcData;
    (void)context;
#endif
}

static int32_t HksAllocateMemForKey(const struct HksParamSet *paramSet, struct HksBlob *key)
{
    uint32_t alg = 0;
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret == HKS_SUCCESS) {
        alg = algParam->uint32Param;
    }

    uint32_t size = MAX_KEY_SIZE;
    if (alg == HKS_ALG_ML_DSA || alg == HKS_ALG_ML_KEM) {
        size = ML_DSA_MAX_KEY_SIZE;
    }
    key->data = (uint8_t *)HksMalloc(size);
    if (key->data == NULL) {
        HKS_LOG_E("malloc fail.");
        return HKS_ERROR_MALLOC_FAIL;
    }

    key->size = size;
    return HKS_SUCCESS;
}

static int32_t CheckKeySecuritySe(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    bool *isSeCalling)
{
#ifdef L2_STANDARD
    struct HksParam *securityLevelParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_SECURITY_LEVEL, &securityLevelParam);
    HKS_IF_TRUE_RETURN(ret != HKS_SUCCESS, HKS_SUCCESS)

    HKS_IF_TRUE_LOGE_RETURN(
        securityLevelParam->uint32Param != HKS_KEY_SECURITY_LEVEL_TEE &&
        securityLevelParam->uint32Param != HKS_KEY_SECURITY_LEVEL_SE,
        HKS_ERROR_INVALID_ARGUMENT,
        "Invalid key security level: %" LOG_PUBLIC "u", securityLevelParam->uint32Param)

    if (securityLevelParam->uint32Param == HKS_KEY_SECURITY_LEVEL_SE) {
        ret = HksSePermissionCheck(processInfo);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Se permission check failed.")

        ret = HksSeIncrementSeCount();
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Failed to increment SE call count.")

        *isSeCalling = true;

        // temp
        securityLevelParam->uint32Param = HKS_KEY_SECURITY_LEVEL_INDEPENDENT_SE;

        struct HksParam *userAuthTypeParam = NULL;
        if (HksGetParam(paramSet, HKS_TAG_USER_AUTH_TYPE, &userAuthTypeParam) == HKS_SUCCESS &&
            (userAuthTypeParam->uint32Param & HKS_USER_AUTH_TYPE_TUI_PIN) != 0) {
            securityLevelParam->uint32Param = HKS_KEY_SECURITY_LEVEL_INDEPENDENT_SE;
        }
    }

    return HKS_SUCCESS;
#else
    (void)processInfo;
    (void)paramSet;
    (void)isSeCalling;
    return HKS_SUCCESS;
#endif
}

static int32_t CheckSeSessionCall(const struct HksProcessInfo *processInfo, bool *isSeCalling)
{
#ifdef L2_STANDARD
    int32_t ret = HksSePermissionCheck(processInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Se permission check failed.")

    ret = HksSeIncrementSeCount();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Failed to increment SE call count.")

    *isSeCalling = true;
    return HKS_SUCCESS;
#else
    (void)processInfo;
    (void)isSeCalling;
    return HKS_SUCCESS;
#endif
}

static void DecrementSeCountByParamSet(bool isSeCalling)
{
#ifdef L2_STANDARD
    if (isSeCalling) {
        (void)HksSeDecrementSeCount();
        return;
    }
#else
    (void)isSeCalling;
#endif
}

void HksIpcServiceGenerateKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob keyOut = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    bool isNoneResponse = false;
    bool isSeCalling = false;

    do {
        ret = HksGenerateKeyUnpack(srcData, &keyAlias, &inParamSet, &keyOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKeyUnpack Ipc fail")

        if (keyOut.data == NULL) {
            isNoneResponse = true;
            ret = HksAllocateMemForKey(inParamSet, &keyOut);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAllocateMemForKey fail, ret = %" LOG_PUBLIC "d", ret)
        }

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeySecuritySe(&processInfo, inParamSet, &isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySe fail, ret = %" LOG_PUBLIC "d", ret)

        struct HksParam *accessTypeParam = NULL;
        ret = HksGetParam(inParamSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &accessTypeParam);
        if (ret == HKS_SUCCESS && accessTypeParam != NULL &&
            accessTypeParam->uint32Param == HKS_AUTH_ACCESS_ALWAYS_VALID) {
            int32_t activeFrontUserId;
            ret = HksGetFrontUserId(&activeFrontUserId);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetFrontUserId fail! ret=%" LOG_PUBLIC "d", ret);
            struct HksParamSet *newParamSet = NULL;
            ret = BuildFrontUserIdParamSet(inParamSet, &newParamSet, activeFrontUserId);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "BuildFrontUserIdParamSet fail! ret=%" LOG_PUBLIC "d", ret);
            ret = HksServiceGenerateKey(&processInfo, &keyAlias, newParamSet, &keyOut);
            HksFreeParamSet(&newParamSet);
        } else {
            ret = HksServiceGenerateKey(&processInfo, &keyAlias, inParamSet, &keyOut);
        }
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceGenerateKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, isNoneResponse ? NULL : &keyOut);

    DecrementSeCountByParamSet(isSeCalling);

    HKS_FREE_BLOB(keyOut);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceImportKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob key = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    bool isSeCalling = false;

    do {
        ret  = HksImportKeyUnpack(srcData, &keyAlias, &paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeySecuritySe(&processInfo, paramSet, &isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySe fail, ret = %" LOG_PUBLIC "d", ret)

        ret =  HksServiceImportKey(&processInfo, &keyAlias, paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceImportKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    DecrementSeCountByParamSet(isSeCalling);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceImportWrappedKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksBlob wrappingKeyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob wrappedKeyData = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    bool isSeCalling = false;

    do {
        ret  = HksImportWrappedKeyUnpack(srcData, &keyAlias, &wrappingKeyAlias, &paramSet, &wrappedKeyData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "unpack data for Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get process info fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckKeySecuritySe(&processInfo, paramSet, &isSeCalling);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeySecuritySe fail, ret = %" LOG_PUBLIC "d", ret)

        ret =  HksServiceImportWrappedKey(&processInfo, &keyAlias, &wrappingKeyAlias, paramSet, &wrappedKeyData);
        HKS_IF_NOT_SUCC_LOGE(ret, "do import wrapped key fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    DecrementSeCountByParamSet(isSeCalling);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceExportPublicKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob key = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret  = HksExportPublicKeyUnpack(srcData, &keyAlias, &paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceExportPublicKey(&processInfo, &keyAlias, paramSet, &key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceExportPublicKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &key : NULL);

    HKS_FREE_BLOB(key);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceDeleteKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;
    do {
        ret  = HksDeleteKeyUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceDeleteKey(&processInfo, &keyAlias, paramSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksIpcServiceDeleteKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceGetKeyParamSet(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksBlob paramSet = { 0, NULL };
    struct HksParamSet *paramSetIn = NULL;
    struct HksParamSet *paramSetOut = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksGetKeyParamSetUnpack(srcData, &keyAlias, &paramSetIn, &paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKeyUnpack Ipc fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksGetProcessInfoForIPC(paramSetIn, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSetIn, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceGetKeyParamSet(&processInfo, &keyAlias, paramSetIn, paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceGetKeyParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        paramSet.size = paramSetOut->paramSetSize;
        paramSet.data = (uint8_t *)paramSetOut;
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &paramSet : NULL);

    HKS_FREE(paramSetOut);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceKeyExist(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret  = HksKeyExistUnpack(srcData, &keyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceKeyExist(&processInfo, &keyAlias, paramSet);
        HKS_IF_TRUE_LOGI_BREAK(ret == HKS_ERROR_NOT_EXIST, "key is not exist");
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceKeyExist fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceGenerateRandom(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksProcessInfo processInfo = { { 0, NULL }, { 0, NULL } };
    struct HksBlob random = { 0, NULL };
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;

    do {
        HKS_IF_TRUE_LOGE_BREAK(srcData == NULL || srcData->data == NULL || srcData->size < sizeof(uint32_t),
            "invalid srcData")

        random.size = *((uint32_t *)(srcData->data));
        HKS_IF_TRUE_LOGE_BREAK(IsInvalidLength(random.size), "invalid size %" LOG_PUBLIC "u", random.size)

        random.data = (uint8_t *)HksMalloc(random.size);
        if (random.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksGetProcessInfoForIPC(NULL, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceGenerateRandom(&processInfo, &random);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceGenerateRandom fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &random : NULL);

    HKS_FREE_BLOB(random);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceSign(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob unsignedData = { 0, NULL };
    struct HksBlob signature = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksSignUnpack(srcData, &keyAlias, &inParamSet, &unsignedData, &signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSignUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceSign(&processInfo, &keyAlias, inParamSet, &unsignedData, &signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceSign fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &signature : NULL);

    HKS_FREE_BLOB(signature);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceVerify(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob unsignedData = { 0, NULL };
    struct HksBlob signature = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksVerifyUnpack(srcData, &keyAlias, &inParamSet, &unsignedData, &signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksVerifyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceVerify(&processInfo, &keyAlias, inParamSet, &unsignedData, &signature);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceVerify fail ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceEncrypt(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob plainText = { 0, NULL };
    struct HksBlob cipherText = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksEncryptDecryptUnpack(srcData, &keyAlias, &inParamSet, &plainText, &cipherText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksEncryptDecryptUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(NULL, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceEncrypt(&processInfo, &keyAlias, inParamSet, &plainText, &cipherText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceEncrypt fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &cipherText : NULL);

    HKS_FREE_BLOB(cipherText);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceDecrypt(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob plainText = { 0, NULL };
    struct HksBlob cipherText = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksEncryptDecryptUnpack(srcData, &keyAlias, &inParamSet, &cipherText, &plainText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksEncryptDecryptUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceDecrypt(&processInfo, &keyAlias, inParamSet, &cipherText, &plainText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceDecrypt fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &plainText : NULL);

    HKS_FREE_BLOB(plainText);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceAgreeKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob privateKey = { 0, NULL };
    struct HksBlob peerPublicKey = { 0, NULL };
    struct HksBlob agreedKey = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksAgreeKeyUnpack(srcData, &inParamSet, &privateKey, &peerPublicKey, &agreedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAgreeKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceAgreeKey(&processInfo, inParamSet, &privateKey, &peerPublicKey, &agreedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceAgreeKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &agreedKey : NULL);

    HKS_FREE_BLOB(agreedKey);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceDeriveKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob masterKey = { 0, NULL };
    struct HksBlob derivedKey = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksDeriveKeyUnpack(srcData, &inParamSet, &masterKey, &derivedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeriveKeyUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceDeriveKey(&processInfo, inParamSet, &masterKey, &derivedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceDeriveKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &derivedKey : NULL);

    HKS_FREE_BLOB(derivedKey);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceMac(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob key = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob inputData = { 0, NULL };
    struct HksBlob mac = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksHmacUnpack(srcData, &key, &inParamSet, &inputData, &mac);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksHmacUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceMac(&processInfo, &key, inParamSet, &inputData, &mac);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceMac fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &mac : NULL);

    HKS_FREE_BLOB(mac);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

static void FreeKeyInfo(uint32_t listCount, struct HksKeyInfo **keyInfoList)
{
    if ((keyInfoList == NULL) || (*keyInfoList == NULL)) {
        return;
    }

    for (uint32_t i = 0; i < listCount; ++i) {
        if ((*keyInfoList)[i].alias.data != NULL) {
            HKS_FREE_BLOB((*keyInfoList)[i].alias);
        }
        if ((*keyInfoList)[i].paramSet != NULL) {
            HKS_FREE((*keyInfoList)[i].paramSet);
            (*keyInfoList)[i].paramSet = NULL;
        }
    }

    HKS_FREE(*keyInfoList);
}

void HksIpcServiceGetKeyInfoList(const struct HksBlob *srcData, const uint8_t *context)
{
    uint32_t inputCount = 0;
    struct HksParamSet *paramSet = NULL;
    struct HksKeyInfo *keyInfoList = NULL;
    struct HksBlob keyInfoListBlob = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksGetKeyInfoListUnpack(srcData, &paramSet, &inputCount, &keyInfoList);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetKeyInfoListUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        uint32_t listCount = inputCount;
        ret = HksServiceGetKeyInfoList(&processInfo, paramSet, keyInfoList, &listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceGetKeyInfoList fail, ret = %" LOG_PUBLIC "d", ret)

        keyInfoListBlob.size = sizeof(listCount);
        for (uint32_t i = 0; i < listCount; ++i) {
            keyInfoListBlob.size += sizeof(keyInfoList[i].alias.size) + ALIGN_SIZE(keyInfoList[i].alias.size) +
                ALIGN_SIZE(keyInfoList[i].paramSet->paramSetSize);
        }

        keyInfoListBlob.data = (uint8_t *)HksMalloc(keyInfoListBlob.size);
        if (keyInfoListBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksGetKeyInfoListPackFromService(&keyInfoListBlob, listCount, keyInfoList);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &keyInfoListBlob : NULL);

    FreeKeyInfo(inputCount, &keyInfoList);
    HKS_FREE_BLOB(keyInfoListBlob);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

int32_t HksAttestAccessControl(struct HksParamSet *paramSet)
{
#ifdef HKS_SUPPORT_ACCESS_TOKEN
    // check permisson for attest ids
    for (uint32_t i = 0; i < sizeof(g_idList) / sizeof(g_idList[0]); i++) {
        for (uint32_t j = 0; j < paramSet->paramsCnt; j++) {
            HKS_IF_TRUE_RETURN(paramSet->params[j].tag == g_idList[i],
                SensitivePermissionCheck("ohos.permission.ACCESS_IDS"))
        }
    }
    // HKS_ATTESTATION_MODE_ANONYMOUS no need check permission
    HKS_IF_TRUE_RETURN(HksAttestIsAnonymous(paramSet), HKS_SUCCESS)

    return SensitivePermissionCheck("ohos.permission.ATTEST_KEY");
#endif
    (void)paramSet;
    return HKS_SUCCESS;
}

void HksIpcServiceAttestKey(const struct HksBlob *srcData, const uint8_t *context, const uint8_t *remoteObject)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *inParamSet = NULL;
    struct HksBlob certChainBlob = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksCertificateChainUnpack(srcData, &keyAlias, &inParamSet, &certChainBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificateChainUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksAttestAccessControl(inParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAttestAccessControl fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceAttestKey(&processInfo, &keyAlias, inParamSet, &certChainBlob, remoteObject);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceAttestKey fail, ret = %" LOG_PUBLIC "d", ret)

        // certChainBlob.size would be 0 if attestation mode is anonymous
        HKS_LOG_I("got certChainBlob size %" LOG_PUBLIC "u", certChainBlob.size);
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &certChainBlob : NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(certChainBlob);
}

static int32_t IpcServiceInit(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *outData)
{
    uint8_t handleData[HANDLE_SIZE] = {0};
    uint8_t tokenData[TOKEN_SIZE] = {0};
    struct HksBlob handle = { sizeof(handleData), handleData };
    struct HksBlob token = { sizeof(tokenData), tokenData };

    int32_t ret = HksServiceInit(processInfo, keyAlias, paramSet, &handle, &token);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "service init failed, ret = %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(handle.size != HANDLE_SIZE || token.size > TOKEN_SIZE, HKS_ERROR_BAD_STATE,
        "invalid handle size[%" LOG_PUBLIC "u], or token size[%" LOG_PUBLIC "u]", handle.size, token.size)

    HKS_IF_TRUE_LOGE_RETURN(outData->size < handle.size + token.size, HKS_ERROR_BUFFER_TOO_SMALL,
        "ipc out size[%" LOG_PUBLIC "u] too small", outData->size)

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(outData->data, outData->size, handle.data, handle.size),
        HKS_ERROR_INSUFFICIENT_MEMORY, "copy outData data failed!")

    if (token.size != 0 &&
        memcpy_s(outData->data + handle.size, outData->size - handle.size, token.data, token.size) != EOK) {
        HKS_LOG_E("copy token failed");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    outData->size = handle.size + token.size;

    return HKS_SUCCESS;
}

void HksIpcServiceInit(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context)
{
    int32_t ret;
    struct HksParamSet *inParamSet = NULL;
    struct HksParamSet *paramSet   = NULL;
    struct HksBlob keyAlias        = { 0, NULL };
    struct HksBlob paramsBlob      = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;

    do {
        ret = HksGetParamSet((struct HksParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        struct HksParamOut params[] = {
            {
                .tag = HKS_TAG_PARAM0_BUFFER,
                .blob = &keyAlias
            }, {
                .tag = HKS_TAG_PARAM1_BUFFER,
                .blob = &paramsBlob
            },
        };

        ret = HksParamSetToParams(paramSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksGetParamSet((struct HksParamSet *)paramsBlob.data, paramsBlob.size, &inParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(inParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = IpcServiceInit(&processInfo, &keyAlias, inParamSet, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ipc service init fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? outData : NULL);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&inParamSet);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceUpdOrFin(const struct HksBlob *paramSetBlob, struct HksBlob *outData,
    const uint8_t *context, bool isUpdate)
{
    int32_t ret;
    bool isSeCalling = false;
    struct HksParamSet *inParamSet = NULL;
    struct HksParamSet *paramSet = NULL;
    struct HksBlob paramsBlob = { 0, NULL };
    struct HksBlob inData = { 0, NULL };
    struct HksBlob handle = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;

    do {
        ret = HksGetParamSet((struct HksParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        struct HksParamOut params[] = {
            { .tag = HKS_TAG_PARAM0_BUFFER, .blob = &paramsBlob },
            { .tag = HKS_TAG_PARAM1_BUFFER, .blob = &handle },
            { .tag = HKS_TAG_PARAM2_BUFFER, .blob = &inData },
        };
        ret = HksParamSetToParams(paramSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksGetParamSet((struct HksParamSet *)paramsBlob.data, paramsBlob.size, &inParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        if (IsSeHandle(&handle)) {
            ret = CheckSeSessionCall(&processInfo, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckSeSessionCall fail, ret = %" LOG_PUBLIC "d", ret)
        }

        ret = isUpdate ? HksServiceUpdate(&handle, &processInfo, inParamSet, &inData, outData) :
            HksServiceFinish(&handle, &processInfo, inParamSet, &inData, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "%" LOG_PUBLIC "s fail, ret = %" LOG_PUBLIC "d",
            isUpdate ? "HksServiceUpdate" : "HksServiceFinish", ret)
    } while (0);

    HksSendResponse(context, ret, (ret == HKS_SUCCESS && outData->size > 0) ? outData : NULL);

    DecrementSeCountByParamSet(isSeCalling);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&inParamSet);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceUpdate(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context)
{
    HksIpcServiceUpdOrFin(paramSetBlob, outData, context, true);
}

void HksIpcServiceFinish(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context)
{
    HksIpcServiceUpdOrFin(paramSetBlob, outData, context, false);
}

void HksIpcServiceAbort(const struct HksBlob *paramSetBlob, struct HksBlob *outData, const uint8_t *context)
{
    (void)outData;
    int32_t ret;
    bool isSeCalling = false;
    struct HksParamSet *inParamSet = NULL;
    struct HksParamSet *paramSet   = NULL;
    struct HksBlob handle          = { 0, NULL };
    struct HksBlob paramsBlob      = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;

    do {
        ret = HksGetParamSet((struct HksParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        struct HksParamOut params[] = {
            {
                .tag = HKS_TAG_PARAM0_BUFFER,
                .blob = &paramsBlob
            }, {
                .tag = HKS_TAG_PARAM1_BUFFER,
                .blob = &handle
            },
        };
        ret = HksParamSetToParams(paramSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksGetParamSet((struct HksParamSet *)paramsBlob.data, paramsBlob.size, &inParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetParamSet fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksGetProcessInfoForIPC(inParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        if (IsSeHandle(&handle)) {
            ret = CheckSeSessionCall(&processInfo, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckSeSessionCall fail, ret = %" LOG_PUBLIC "d", ret)
        }

        ret = HksServiceAbort(&handle, &processInfo, inParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceAbort fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    DecrementSeCountByParamSet(isSeCalling);

    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&inParamSet);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcErrorResponse(const uint8_t *context)
{
    HksSendResponse(context, HKS_ERROR_IPC_MSG_FAIL, NULL);
}

void HksIpcServiceListAliases(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksParamSet *paramSet = NULL;
    struct HksKeyAliasSet *keyAliasSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksBlob outBlob = { 0, NULL };
    int32_t ret;

    do {
        ret = HksListAliasesUnpack(srcData, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksListAliasesUnpack fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceListAliases(&processInfo, paramSet, &keyAliasSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceListAliases fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksListAliasesPackFromService(keyAliasSet, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksListAliasesPackFromService fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    // query success and key size is not 0
    HksSendResponse(context, ret, ret == HKS_SUCCESS && outBlob.size != 0 ? &outBlob : NULL);

    HksFreeKeyAliasSet(keyAliasSet);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
    HKS_FREE_BLOB(outBlob);
}

void HksIpcServiceRenameKeyAlias(const struct HksBlob *srcData, const uint8_t *context)
{
    int32_t ret;
    struct HksBlob oldKeyAlias = { 0, NULL };
    struct HksBlob newKeyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    do {
        ret  = HksRenameKeyAliasUnpack(srcData, &oldKeyAlias, &newKeyAlias, &paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksRenameKeyAliasUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceRenameKeyAlias(&processInfo, &oldKeyAlias, paramSet, &newKeyAlias);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceRenameKeyAliasy fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcChangeStorageLevel(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *srcParamSet = NULL;
    struct HksParamSet *destParamSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksChangeStorageLevelUnpack(srcData, &keyAlias, &srcParamSet, &destParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksChangeStorageLevelUnpack Ipc fail")

        ret = HksGetProcessInfoForIPC(srcParamSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(srcParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
            "srcParamSet HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(destParamSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
            "destParamSet HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceChangeStorageLevel(&processInfo, &keyAlias, srcParamSet, destParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceChangeStorageLevel fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcWrapKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob wrappedKey = { 0, NULL };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksPluginCheck();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "api not support")

        ret  = HksWrapKeyUnpack(srcData, &keyAlias, &paramSet, &wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "unpack data for Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceWrapKey(&processInfo, &keyAlias, paramSet, &wrappedKey);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceWrapKey fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &wrappedKey : NULL);

    HKS_FREE_BLOB(wrappedKey);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

static int32_t CheckWrappedKeySeVersion(const struct HksBlob *wrappedData, bool *isSeWrappedKey)
{
    HKS_IF_TRUE_LOGE_RETURN(wrappedData->size < sizeof(uint32_t), HKS_ERROR_BUFFER_TOO_SMALL,
        "invalid wrapped key size: %" LOG_PUBLIC "u", wrappedData->size);

    uint32_t version = *(uint32_t *)wrappedData->data;
    if (version == HKS_WRAP_KEY_BY_HUK_VERSION_SE) {
        *isSeWrappedKey = true;
    } else if (version == HKS_WRAP_KEY_BY_HUK_VERSION_INDEPENDENT_SE) {
        *isSeWrappedKey = true;
    }

    return HKS_SUCCESS;
}

void HksIpcUnwrapKey(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksBlob wrappedKey = { 0, NULL };
    struct HksProcessInfo processInfo = { { 0, NULL }, { 0, NULL }, 0, 0 };
    int32_t ret;
    bool isSeCalling = false;

    do {
        ret = HksPluginCheck();
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "api not support")

        ret  = HksUnwrapKeyUnpack(srcData, &keyAlias, &paramSet, &wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "unpack data for Ipc fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        bool isSeWrappedKey = false;
        ret = CheckWrappedKeySeVersion(&wrappedKey, &isSeWrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckWrappedKeySeVersion fail, ret = %" LOG_PUBLIC "d", ret)

        if (isSeWrappedKey) {
            ret = CheckSeSessionCall(&processInfo, &isSeCalling);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckSeSessionCall fail, ret = %" LOG_PUBLIC "d", ret)
        }

        ret = HksServiceUnwrapKey(&processInfo, &keyAlias, paramSet, &wrappedKey);
        HKS_IF_NOT_SUCC_LOGE(ret, "HksServiceUnwrapKey, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksSendResponse(context, ret, NULL);

    DecrementSeCountByParamSet(isSeCalling);

    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

static int32_t CheckAndBuildSharedKeyParamSet(const struct HksBlob *sharedKeyAlias,
    const struct HksParamSet *sharedKeyParamSet, struct HksParamSet **newSharedKeyParamSet)
{
    int32_t ret = HksCheckBlobAndParamSet(sharedKeyAlias, sharedKeyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NEW_INVALID_ARGUMENT, "CheckAndBuildSharedKeyParamSet fail")

    ret = HksCheckParamSet(sharedKeyParamSet, sharedKeyParamSet->paramSetSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check sharedKeyParamSet failed, ret = %" LOG_PUBLIC "d", ret)

    ret = HksInitParamSet(newSharedKeyParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init paramSet fail")
    do {
        ret = HksAddParams(*newSharedKeyParamSet, sharedKeyParamSet->params, sharedKeyParamSet->paramsCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckAndBuildSharedKeyParamSet add paramset fail")

        struct HksParam keyalias = {
            .tag = HKS_TAG_KEY_ALIAS,
            .blob = *sharedKeyAlias,
        };
        ret = HksAddParams(*newSharedKeyParamSet, &keyalias, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param attestMode fail")

        ret = HksBuildParamSet(newSharedKeyParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramSet fail")

        return HKS_SUCCESS;
    } while (false);

    HksFreeParamSet(newSharedKeyParamSet);
    return ret;
}

void HksIpcServiceEncapsulate(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksBlob sharedKeyAlias = { 0, NULL };
    struct HksBlob responseBlob = { 0, NULL };
    struct HksParamSet *paramSet = NULL;
    struct HksParamSet *newParamSet = NULL;
    struct HksParamSet *sharedKeyParamSet = NULL;
    struct HksEncapsulationResult encapResult = { { 0, NULL }, { 0, NULL } };
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    int32_t ret;

    do {
        ret = HksEncapsulateUnpack(srcData, &keyAlias, &paramSet, &sharedKeyAlias,
            &sharedKeyParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksEncapsulateUnpack fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckAndBuildSharedKeyParamSet(&sharedKeyAlias, sharedKeyParamSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check keyAlias and paramSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceEncapsulate(&processInfo, &keyAlias, paramSet, newParamSet, &encapResult);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceEncapsulate fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksEncapsulateResponsePack(&encapResult, &responseBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksEncapsulateResponsePack fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);
    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &responseBlob : NULL);

    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    HksFreeParamSet(&newParamSet);
    HKS_MEMSET_FREE_BLOB(responseBlob);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}

void HksIpcServiceDecapsulate(const struct HksBlob *srcData, const uint8_t *context)
{
    struct HksBlob keyAlias = { 0, NULL };
    struct HksBlob sharedKeyAlias = { 0, NULL };
    struct HksBlob encapOrsharedSecret = { 0, NULL };
    struct HksParamSet *newSharedKeyParamSet = NULL;
    struct HksParamSet *paramSet = NULL;
    struct HksParamSet *sharedKeyParamSet = NULL;
    struct HksProcessInfo processInfo = HKS_PROCESS_INFO_INIT_VALUE;
    struct HksBlob responseBlob = { 0, NULL };
    int32_t ret;

    do {
        uint32_t offset = 0;
        ret = HksKeyParamUnpack(srcData, &keyAlias, &paramSet, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDecapsulateUnpack fail")

        ret = HksDecapsulateUnpack(srcData, &sharedKeyAlias, &sharedKeyParamSet,
            &encapOrsharedSecret, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDecapsulateUnpack fail")

        ret = HksGetProcessInfoForIPC(paramSet, context, &processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetProcessInfoForIPC fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckAcrossAccountsPermission(paramSet, processInfo.userIdInt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckAcrossAccountsPermission fail, ret = %" LOG_PUBLIC "d", ret)

        ret = CheckAndBuildSharedKeyParamSet(&sharedKeyAlias, sharedKeyParamSet, &newSharedKeyParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check and build sharedKeyParamSet failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksServiceDecapsulate(&processInfo, &keyAlias, paramSet,
            newSharedKeyParamSet, &encapOrsharedSecret);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksServiceDecapsulate fail, ret = %" LOG_PUBLIC "d", ret)

        uint32_t responseSize = sizeof(uint32_t);
        if (encapOrsharedSecret.size > 0) {
            responseSize += ALIGN_SIZE(encapOrsharedSecret.size);
        } else {
            responseSize += DEFAULT_ALIGN_MASK_SIZE;
        }
        responseBlob.size = responseSize;
        ret = HKS_ERROR_MALLOC_FAIL;
        responseBlob.data = (uint8_t *)HksMalloc(responseBlob.size);
        HKS_IF_NULL_BREAK(responseBlob.data)

        offset = 0;
        ret = CopyBlobToBufferForEmptyData(&encapOrsharedSecret, &responseBlob, &offset);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksIpcServiceDecapsulate Copy sharedSecret to responseBlob fail.")
    } while (0);
    HksSendResponse(context, ret, ret == HKS_SUCCESS ? &responseBlob : NULL);

    HksFreeParamSet(&newSharedKeyParamSet);
    HKS_MEMSET_FREE_BLOB(responseBlob);
    HKS_MEMSET_FREE_BLOB(encapOrsharedSecret);
    HKS_FREE_BLOB(processInfo.processName);
    HKS_FREE_BLOB(processInfo.userId);
}
