/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hks_core_service_key_attest.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_ability.h"
#include "dcm_attest.h"
#include "hks_auth.h"
#include "hks_base_check.h"
#include "hks_check_paramset.h"
#include "hks_client_service_adapter_common.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_core_service_three_stage.h"
#include "hks_crypto_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_secure_access.h"
#include "hks_sm_import_wrap_key.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_util.h"

#include "securec.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

#ifndef _CUT_AUTHENTICATE_

#ifdef HKS_SUPPORT_API_ATTEST_KEY
static int32_t CheckAttestKeyParams(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(key), HKS_ERROR_INVALID_ARGUMENT, "invalid key!")

    if ((CheckBlob(certChain) != HKS_SUCCESS) || (certChain->size < HKS_ATTEST_CERT_SIZE)) {
        HKS_LOG_E("invalid cert chain!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_IF_NOT_SUCC_LOGE_RETURN(HksCheckParamSetValidity(paramSet), HKS_ERROR_INVALID_ARGUMENT, "invalid paramSet!")

    return HKS_SUCCESS;
}
#endif

int32_t HksCoreAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain)
{
#ifdef HKS_SUPPORT_API_ATTEST_KEY
    int32_t ret = CheckAttestKeyParams(key, paramSet, certChain);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct HksParam *certTypeParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_ATTESTATION_CERT_TYPE, &certTypeParam);
    if (ret == HKS_SUCCESS) {
        HKS_LOG_E("not support compatible rsa attest");
        return HKS_ERROR_NOT_SUPPORTED;
    } else if (ret != HKS_ERROR_PARAM_NOT_EXIST) {
        HKS_LOG_E("get attest cert type failed");
        return ret;
    }

    struct HksKeyNode *keyNode = HksGenerateKeyNode(key);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_ERROR_CORRUPT_FILE, "generate keynode failed")

    ret = HksProcessIdentityVerify(keyNode->paramSet, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("access control failed");
        HksFreeKeyNode(&keyNode);
        return ret;
    }

    struct HksBlob rawKey;
    HksGetRawKey(keyNode->paramSet, &rawKey);
    struct HksParam *attestParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_ATTESTATION_MODE, &attestParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get attestation mode failed");
        HksFreeKeyNode(&keyNode);
        return ret;
    }
 
    if (attestParam->uint32Param == HKS_ATTESTATION_MODE_ANONYMOUS) {
        ret = CreateAttestCertChain(true, keyNode->paramSet, paramSet, certChain, &rawKey);
    } else {
        ret = CreateAttestCertChain(false, keyNode->paramSet, paramSet, certChain, &rawKey);
    }
    HksFreeKeyNode(&keyNode);
    HKS_FREE_BLOB(rawKey);
    return ret;
#else
    (void)key;
    (void)paramSet;
    (void)certChain;
    return HKS_ERROR_NOT_SUPPORTED;
#endif
}

#endif /* _CUT_AUTHENTICATE_ */