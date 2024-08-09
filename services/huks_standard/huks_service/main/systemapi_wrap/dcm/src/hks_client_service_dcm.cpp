/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_cfi.h"
#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "hks_template.h"
#include "hks_type.h"

ENABLE_CFI(int32_t DcmGenerateCertChain(struct HksBlob *cert, const uint8_t *remoteObject))
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(cert), HKS_ERROR_INVALID_ARGUMENT, "invalid in cert");
    AttestFunction fun = HksOpenDcmFunction();
    HKS_IF_NULL_LOGE_RETURN(fun, HKS_ERROR_UNKNOWN_ERROR, "HksOpenDcmFunction failed");
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
    } while (false);
    return ret;
}

#endif // HKS_UNTRUSTED_RUNNING_ENV
