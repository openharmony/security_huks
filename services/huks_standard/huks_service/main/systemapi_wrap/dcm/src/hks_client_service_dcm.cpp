/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef HKS_UNTRUSTED_RUNNING_ENV

#include "hks_client_service_dcm.h"

#include <cinttypes>
#include <securec.h>
#include "hks_util.h"
#include "hks_cfi.h"
#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_plugin_def.h"

#define HKS_DCM_VALID_TIME_SECONDS 3600

ENABLE_CFI(int32_t DcmGenerateCertChain(struct HksBlob *cert, const uint8_t *remoteObject))
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(cert), HKS_ERROR_NEW_INVALID_ARGUMENT, "invalid in cert");
    AttestFunction fun = HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey");
    HKS_IF_NULL_LOGE_RETURN(fun, HKS_ERROR_UNKNOWN_ERROR, "HksGetDcmFunction failed");
    int ret = HKS_ERROR_UNKNOWN_ERROR;
    do {
        DcmAnonymousRequest request = {
            .blob = { .size = cert->size, .data = cert->data },
            .requestId = 0,
        };
        // We got a requestId after invoking DcmAnonymousAttestKey function,
        // and the implementation of DcmAnonymousAttestKey will invoke our HksDcmCallback in a new thread.
        // To avoid that the new thread will call HksDcmCallback before
        // HksDcmCallbackHandlerSetRequestIdWithoutLock, we bind the getting requestId operation and setting
        // requestId openration with one lock guard.
        std::lock_guard<std::mutex> lockGuard(HksDcmCallbackHandlerGetMapMutex());
        ret = fun(&request, [](DcmAnonymousResponse *response) {
            HksDcmCallback(response);
        });
        HKS_LOG_I("got requestId %" LOG_PUBLIC PRIu64, request.requestId);
        if (ret != DCM_SUCCESS) {
            HKS_LOG_E("DcmAnonymousAttestKey failed %" LOG_PUBLIC "d", ret);
            ret = HUKS_ERR_CODE_EXTERNAL_ERROR;
            // We will not add callback instance into map and ignore callback in case of error.
            break;
        }
        ret = HksDcmCallbackHandlerSetRequestIdWithoutLock(remoteObject, request.requestId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDcmCallbackHandlerSetRequestIdWithoutLock failed %" LOG_PUBLIC "d", ret)
        return HKS_SUCCESS;
    } while (0);
    return ret;
}

static int32_t ParseSeAttestKeyData(const struct HksBlob *seCert, struct HksBlob *seKeyBlob,
    struct HksBlob *paramSetBlob, struct HksBlob *certChain)
{
    uint8_t *buf = seCert->data;
    uint32_t offset = 0;

    HKS_IF_TRUE_LOGE_RETURN(offset + sizeof(uint32_t) > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for seKeyBlob size");

    uint32_t seKeyBlobSize = *(static_cast<uint32_t *>(static_cast<void *>(buf + offset)));
    offset += sizeof(uint32_t);

    HKS_IF_TRUE_LOGE_RETURN(offset + seKeyBlobSize > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for seKeyBlob data");

    seKeyBlob->size = seKeyBlobSize;
    seKeyBlob->data = buf + offset;
    offset += seKeyBlobSize;

    HKS_IF_TRUE_LOGE_RETURN(offset + sizeof(uint32_t) > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for paramSet size");

    uint32_t paramSetSize = *(static_cast<uint32_t *>(static_cast<void *>(buf + offset)));
    offset += sizeof(uint32_t);

    HKS_IF_TRUE_LOGE_RETURN(offset + paramSetSize > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for paramSet data");

    paramSetBlob->size = paramSetSize;
    paramSetBlob->data = buf + offset;
    offset += paramSetSize;

    HKS_IF_TRUE_LOGE_RETURN(offset + sizeof(uint32_t) > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for certChain size");

    uint32_t certChainSize = *(static_cast<uint32_t *>(static_cast<void *>(buf + offset)));
    offset += sizeof(uint32_t);

    HKS_IF_TRUE_LOGE_RETURN(offset + certChainSize > seCert->size, HKS_ERROR_INVALID_ARGUMENT,
        "seCert data too small for certChain data");

    certChain->size = certChainSize;
    certChain->data = buf + offset;

    HKS_LOG_I("data size: seKeyBlob: %" LOG_PUBLIC "u, paramset: %" LOG_PUBLIC "u, certChain: %" LOG_PUBLIC "u",
        seKeyBlob->size, paramSetBlob->size, certChain->size);
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t DcmSeGenerateCertChain(struct HksBlob *seCert, const uint8_t *remoteObject))
{
    HKS_LOG_I("enter DcmSeGenerateCertChain");
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(seCert), HKS_ERROR_NEW_INVALID_ARGUMENT, "invalid in seCert");

    struct HksBlob seKeyBlob = { 0, NULL };
    struct HksBlob paramSetBlob = { 0, NULL };
    struct HksBlob certChain = { 0, NULL };

    int32_t ret = ParseSeAttestKeyData(seCert, &seKeyBlob, &paramSetBlob, &certChain);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "ParseSeAttestKeyData failed");

    SeAttestFunction fun = HksGetDcmFunction<SeAttestFunction>("DcmAnonymousAttestKeySe");
    HKS_IF_NULL_LOGE_RETURN(fun, HKS_ERROR_UNKNOWN_ERROR, "HksGetDcmFunction failed");

    ret = HKS_ERROR_UNKNOWN_ERROR;
    do {
        DcmAnonymousRequest request = {
            .blob = { .size = certChain.size, .data = certChain.data },
            .requestId = 0,
        };

        DcmBlob dcmSeKeyBlob = { .size = seKeyBlob.size, .data = seKeyBlob.data };
        DcmBlob dcmParamSetBlob = { .size = paramSetBlob.size, .data = paramSetBlob.data };

        std::lock_guard<std::mutex> lockGuard(HksDcmCallbackHandlerGetMapMutex());
        ret = fun(&dcmSeKeyBlob, &dcmParamSetBlob, &request, [](DcmAnonymousResponse *response) {
            HksDcmCallback(response);
        });
        HKS_LOG_I("got requestId %" LOG_PUBLIC PRIu64, request.requestId);
        if (ret != DCM_SUCCESS) {
            HKS_LOG_E("DcmAnonymousAttestKeySe failed %" LOG_PUBLIC "d", ret);
            ret = HUKS_ERR_CODE_EXTERNAL_ERROR;
            break;
        }
        ret = HksDcmCallbackHandlerSetRequestIdWithoutLock(remoteObject, request.requestId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDcmCallbackHandlerSetRequestIdWithoutLock failed %" LOG_PUBLIC "d", ret)
        return HKS_SUCCESS;
    } while (0);
    return ret;
}

ENABLE_CFI(int32_t DcmLocalGenerateCertChain(const struct HksProcessInfo *processInfo, struct HksBlob *cert,
    const uint8_t *remoteObject))
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(cert), HKS_ERROR_INVALID_ARGUMENT, "invalid in cert");
    LocalAttestFunction fun = HksGetDcmFunction<LocalAttestFunction>("DcmLocalApplyAnonymousAttestKey");
    HKS_IF_NULL_LOGE_RETURN(fun, HKS_ERROR_UNKNOWN_ERROR, "HksGetDcmFunction DcmLocalApplyAnonymousAttestKey failed");

    uint64_t timestapSe = 0;
    int32_t ret = HksGetCurTime(&timestapSe);
    DcmApplyAnonymousRequest request = {
        .callingUid = processInfo->uidInt,
        .curUTCTime = timestapSe,
        .tokenID = processInfo->accessTokenId,
        .remainValidatePeriod = HKS_DCM_VALID_TIME_SECONDS,
        .requestId = 0,
    };
    do {
        // We got a requestId after invoking DcmAnonymousAttestKey function,
        // and the implementation of DcmAnonymousAttestKey will invoke our HksDcmCallback in a new thread.
        // To avoid that the new thread will call HksDcmCallback before
        // HksDcmCallbackHandlerSetRequestIdWithoutLock, we bind the getting requestId operation and setting
        // requestId openration with one lock guard.
        std::lock_guard<std::mutex> lockGuard(HksDcmOfflineCallbackHandlerGetMapMutex());
        ret = fun(&request, (DcmBlob *)cert, [](DcmAnonymousResponse *response) {
            HksDcmOfflineCallback(response);
        });
        HKS_LOG_I("got requestId %" LOG_PUBLIC PRIu64, request.requestId);
        if (ret != DCM_SUCCESS) {
            HKS_LOG_E("DcmAnonymousAttestKey failed %" LOG_PUBLIC "d", ret);
            ret = HUKS_ERR_CODE_EXTERNAL_ERROR;
            // We will not add callback instance into map and ignore callback in case of error.
            break;
        }
        ret = HksDcmOfflineCallbackHandlerSetRequestIdWithoutLock(remoteObject, request.requestId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDcmCallbackHandlerSetRequestIdWithoutLock failed %" LOG_PUBLIC "d", ret)
        return HKS_SUCCESS;
    } while (0);
    return ret;
}

#endif // HKS_UNTRUSTED_RUNNING_ENV
