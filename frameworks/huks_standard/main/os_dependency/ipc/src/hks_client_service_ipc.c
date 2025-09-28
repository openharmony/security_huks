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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_client_ipc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hks_common_check.h"
#include "hks_check_paramset.h"
#include "hks_ipc_check.h"
#include "hks_client_ipc_serialization.h"
#include "hks_ipc_slice.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_request.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_inner.h"
#include "huks_service_ipc_interface_code.h"
#include "securec.h"

#ifdef HKS_L1_SMALL
#include "hks_samgr_client.h"
#include <unistd.h>
#endif

int32_t HksClientInitialize(void)
{
#ifdef HKS_L1_SMALL
    for (uint32_t i = 0; i < HKS_MAX_RETRY_TIME; ++i) {
        IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(HKS_SAMGR_SERVICE, HKS_SAMGR_FEATRURE);
        if (iUnknown != NULL) {
            return HKS_SUCCESS;
        }
        usleep(HKS_SLEEP_TIME_FOR_RETRY);
    }
    HKS_LOG_E("HUKS service is not ready!");
    return HKS_ERROR_BAD_STATE;
#else
    return HKS_SUCCESS;
#endif
}

int32_t HksClientRefreshKeyInfo(void)
{
    return HKS_SUCCESS;
}

static int32_t BuildParamSetNotNull(const struct HksParamSet *paramSetIn, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *tmpParamSet = NULL;
    do {
        if (paramSetIn != NULL) {
            ret = HksCheckParamSet(paramSetIn, paramSetIn->paramSetSize);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check paramSet failed")
        }

        ret = HksInitParamSet(&tmpParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksInitParamSet failed")

        if (paramSetIn != NULL) {
            ret = HksAddParams(tmpParamSet, paramSetIn->params, paramSetIn->paramsCnt);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAddParams failed")
        }
        ret = HksBuildParamSet(&tmpParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksBuildParamSet failed")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&tmpParamSet);
        return ret;
    }
    *paramSetOut = tmpParamSet;
    return ret;
}

int32_t HksClientRegisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
    HKS_LOG_D("======HksClientRegisterProvider enter RegisterProvider");
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;

    inBlob.size = sizeof(name->size) + ALIGN_SIZE(name->size) + ALIGN_SIZE(paramSetIn->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcDeleteKey(name, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientRegisterProvider fail")

        ret = HksDeleteKeyPack(name, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksRegisterProviderPack fail")

        ret = HksSendRequest(HKS_MSG_EXT_REGISTER, &inBlob, NULL, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientUnregisterProvider(const struct HksBlob *name, const struct HksParamSet *paramSetIn)
{
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;

    inBlob.size = sizeof(name->size) + ALIGN_SIZE(name->size) + ALIGN_SIZE(paramSetIn->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcDeleteKey(name, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientUnregisterProvider fail")

        ret = HksDeleteKeyPack(name, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksRegisterProviderPack fail")

        ret = HksSendRequest(HKS_MSG_EXT_UNREGISTER, &inBlob, NULL, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientExportProviderCertificates(const struct HksBlob *name, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet) 
{
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;
        

    if(certSet == NULL || certSet->certs != NULL || certSet->count != 0) {
        // TODO:错误码怎么写
        HKS_LOG_E("certSet is invalid, must be a empty set");
        return HKS_ERROR_NULL_POINTER;
    }

    // TODO:这个地方提前申请多大的内存合适
    outBlob.size = sizeof(HKS_MAX_KEY_ALIAS_COUNT) + (HKS_MAX_KEY_ALIAS_COUNT * HKS_MAX_KEY_ALIAS_LEN);
    outBlob.data = (uint8_t *)HksMalloc(outBlob.size);
    HKS_IF_NULL_RETURN(outBlob.data, HKS_ERROR_MALLOC_FAIL);

    inBlob.size = sizeof(name->size) + ALIGN_SIZE(name->size) + ALIGN_SIZE(paramSetIn->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcDeleteKey(name, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientExportProviderCertificates fail");

        ret = HksDeleteKeyPack(name, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportProviderCertificatesPack fail");

        ret = HksSendRequest(HKS_MSG_EXT_EXPORT_PROVIDER_CERTIFICATES, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret);    

        ret = HksCertificatesUnpackFromService(&outBlob, certSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificateChainUnpackFromService fail, ret = %" LOG_PUBLIC "d", ret);
    } while (0);

    HKS_IF_NOT_SUCC_LOGE(ret, "HksClientExportProviderCertificates fail, ret = %" LOG_PUBLIC "d", ret);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);

    return 0;
}

int32_t HksClientExportCertificate(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;

    if(certSet == NULL || certSet->certs != NULL || certSet->count != 0) {
        // TODO:错误码怎么写
        HKS_LOG_E("certSet is invalid, must be a empty set");
        return HKS_ERROR_NULL_POINTER;
    }

    // TODO:这个地方提前申请多大的内存合适
    outBlob.size = sizeof(HKS_MAX_KEY_ALIAS_COUNT) + (HKS_MAX_KEY_ALIAS_COUNT * HKS_MAX_KEY_ALIAS_LEN);
    outBlob.data = (uint8_t *)HksMalloc(outBlob.size);
    HKS_IF_NULL_RETURN(outBlob.data, HKS_ERROR_MALLOC_FAIL);

    inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + ALIGN_SIZE(paramSetIn->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcDeleteKey(index, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientExportCertificate fail");

        ret = HksDeleteKeyPack(index, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportProviderCertificatesPack fail");

        ret = HksSendRequest(HKS_MSG_EXT_EXPORT_CERTIFICATE, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret);    

        ret = HksCertificatesUnpackFromService(&outBlob, certSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificateChainUnpackFromService fail, ret = %" LOG_PUBLIC "d", ret);
    } while (0);

    HKS_IF_NOT_SUCC_LOGE(ret, "HksClientExportProviderCertificates fail, ret = %" LOG_PUBLIC "d", ret);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);

    return 0;
}

int32_t HksClientOpenRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn,
    struct HksBlob *remoteHandleOut)
{
    // TODO:出参不需要传递？ 没有提前分配内存此处可能有问题
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    // TODO remoteHandleOut必须是一个空的，否则报错， size == 0, data == NULL

    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcExportPublicKey(index, newParamSet, remoteHandleOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientOpenRemoteHandle fail")

        inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + sizeof(remoteHandleOut->size) +
            ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksExportPublicKeyPack(index, newParamSet, remoteHandleOut, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksOpenRemoteHandlePack fail")

        ret = HksSendRequest(HKS_MSG_EXT_OPEN_REMOTE_HANDLE, &inBlob, remoteHandleOut, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientAuthUkeyPin(const struct HksBlob *index, const struct HksParamSet *paramSetIn, uint32_t *outStatus, uint32_t *retryCount)
{
    int32_t ret;

    if (retryCount == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksBlob inBlob = { 0, NULL };
    /**
    *                +---------------------------+
    * outBlob:       | uint32_t   | uint32_t     |
    *                | outStatus  |  retryCount  |
    *                +---------------------------+
    */
    struct HksBlob outBlob = { sizeof(int32_t) * 2, (uint8_t *)malloc(sizeof(int32_t) * 2) };
    struct HksParamSet *newParamSet = NULL;
    if (outBlob.data == NULL) {
        HKS_FREE_BLOB(inBlob);
        return HKS_ERROR_MALLOC_FAIL;
    }

    inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + ALIGN_SIZE(paramSetIn->paramSetSize) + sizeof(outBlob.size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcGenerateKey(index, paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcAuthUkeyPin fail");

        ret = HksGenerateKeyPack(&inBlob, index, paramSetIn, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAuthUkeyPinPack fail");

        ret = HksSendRequest(HKS_MSG_EXT_AUTH_UKEY_PIN, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret);

        if (outBlob.data != NULL && ret != HKS_SUCCESS && outBlob.size >= sizeof(int32_t) * 2) {
            // PIN码错误处理，上层感知outStatus和retryCount，用于抛出异常
            (void)memcpy_s(outStatus, sizeof(int32_t), outBlob.data, sizeof(int32_t));
            (void)memcpy_s(retryCount, sizeof(int32_t), outBlob.data + sizeof(int32_t), sizeof(int32_t));
            ret = HUKS_ERR_CODE_PIN_CODE_ERROR;
        }
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);

    return ret;
}

int32_t HksClientGetUkeyPinAuthState(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    // TODO:出参不需要传递？ 没有提前分配内存此处可能有问题
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob outBlob = { 0, NULL };

    inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + ALIGN_SIZE(paramSetIn->paramSetSize) +
        sizeof(outBlob.size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    
    if (paramSetOut != NULL) {
        outBlob.size = paramSetOut->paramSetSize;
        outBlob.data = (uint8_t *)paramSetOut;
    }

    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksCheckIpcGenerateKey(index, paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcGetUkeyPinAuthState fail");

        ret = HksGenerateKeyPack(&inBlob, index, newParamSet, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetUkeyPinAuthStatePack fail");

        ret = HksSendRequest(HKS_MSG_EXT_GET_UKEY_PIN_AUTH_STATE, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)

        if (paramSetOut != NULL) {
            ret = HksFreshParamSet(paramSetOut, false);
            HKS_IF_NOT_SUCC_LOGE(ret, "FreshParamSet fail, ret = %" LOG_PUBLIC "d", ret)
        }
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientGetRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn, struct HksBlob *remoteHandleOut)
{
    // TODO:出参不需要传递？ 没有提前分配内存此处可能有问题
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    // TODO： remoteHandleOut必须是一个空的，否则报错， size == 0, data == NULL
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcExportPublicKey(index, newParamSet, remoteHandleOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcGetRemoteHandle fail")

        inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + sizeof(remoteHandleOut->size) +
            ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksExportPublicKeyPack(index, newParamSet, remoteHandleOut, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetRemoteHandlePack fail")

        ret = HksSendRequest(HKS_MSG_EXT_GET_REMOTE_HANDLE, &inBlob, remoteHandleOut, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientCloseRemoteHandle(const struct HksBlob *index, const struct HksParamSet *paramSetIn)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size) + ALIGN_SIZE(newParamSet->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcDeleteKey(index, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcCloseRemoteHandle fail")

        ret = HksDeleteKeyPack(index, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCloseRemoteHandlePack fail")

        ret = HksSendRequest(HKS_MSG_EXT_CLOSE_REMOTE_HANDLE, &inBlob, NULL, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientGetPinAuthState(const struct HksBlob *index, uint32_t *stateOut)
{
    // TODO: 接口不清晰
    return 0;
}

int32_t HksClientClearPinAuthState(const struct HksBlob *index)
{
    HKS_LOG_D("======HksClientRegisterProvider enter RegisterProvider");
    int32_t ret;

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(index->size) + ALIGN_SIZE(index->size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = CheckBlob(index);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksClientClearPinAuthState fail")

        ret = HksClearPinAuthStatePack(index, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksClientClearPinAuthStatePack fail")

        ret = HksSendRequest(HKS_MSG_EXT_CLEAR_PIN_AUTH_STATE, &inBlob, NULL, NULL);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientUkeySign(const struct HksBlob *index, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
    // TODO:出参不需要传递？ 没有提前分配内存此处可能有问题
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = ALIGN_SIZE(paramSetIn->paramSetSize) + sizeof(index->size) + ALIGN_SIZE(index->size) +
        sizeof(srcData->size) + ALIGN_SIZE(srcData->size) + sizeof(signatureOut->size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcAgreeKey(paramSetIn, index, srcData, signatureOut);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcUkeySign fail")
    

        ret = HksAgreeKeyPack(&inBlob, newParamSet, index, srcData, signatureOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksUkeySignPack fail")

        ret = HksSendRequest(HKS_MSG_EXT_UKEY_SIGN, &inBlob, signatureOut, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    struct HksParamSet *paramSetOut)
{
    int32_t ret = HksCheckIpcGenerateKey(keyAlias, paramSetIn);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcGenerateKey fail")

    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSetIn->paramSetSize) +
        sizeof(outBlob.size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)
    if (paramSetOut != NULL) {
        outBlob.size = paramSetOut->paramSetSize;
        outBlob.data = (uint8_t *)paramSetOut;
    }

    do {
        ret = HksGenerateKeyPack(&inBlob, keyAlias, paramSetIn, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGenerateKeyPack fail")

        ret = HksSendRequest(HKS_MSG_GEN_KEY, &inBlob, &outBlob, paramSetIn);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)

        if (paramSetOut != NULL) {
            ret = HksFreshParamSet(paramSetOut, false);
            HKS_IF_NOT_SUCC_LOGE(ret, "FreshParamSet fail, ret = %" LOG_PUBLIC "d", ret)
        }
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientImportKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *key)
{
    int32_t ret = HksCheckIpcImportKey(keyAlias, paramSet, key);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcImportKey fail")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSet->paramSetSize) +
        sizeof(key->size) + ALIGN_SIZE(key->size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = HksImportKeyPack(&inBlob, keyAlias, paramSet, key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportKeyPack fail")

        ret = HksSendRequest(HKS_MSG_IMPORT_KEY, &inBlob, NULL, paramSet);
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientExportPublicKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *key)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    do {
        ret = BuildParamSetNotNull(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcExportPublicKey(keyAlias, newParamSet, key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcExportPublicKey fail")

        inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + sizeof(key->size) +
            ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksExportPublicKeyPack(keyAlias, newParamSet, key, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksExportPublicKeyPack fail")

        ret = HksSendRequest(HKS_MSG_EXPORT_PUBLIC_KEY, &inBlob, key, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret = HksCheckIpcImportWrappedKey(keyAlias, wrappingKeyAlias, paramSet, wrappedKeyData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksClientImportWrappedKey fail")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
                  sizeof(wrappingKeyAlias->size) + ALIGN_SIZE(wrappingKeyAlias->size) +
                  ALIGN_SIZE(paramSet->paramSetSize) +
                  sizeof(wrappedKeyData->size) + ALIGN_SIZE(wrappedKeyData->size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = HksImportWrappedKeyPack(&inBlob, keyAlias, wrappingKeyAlias, paramSet, wrappedKeyData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksImportWrappedKeyPack fail")

        ret = HksSendRequest(HKS_MSG_IMPORT_WRAPPED_KEY, &inBlob, NULL, paramSet);
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    do {
        ret = BuildParamSetNotNull(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcDeleteKey(keyAlias, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcDeleteKey fail")

        inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksDeleteKeyPack(keyAlias, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeleteKeyPack fail")

        ret = HksSendRequest(HKS_MSG_DELETE_KEY, &inBlob, NULL, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientGetKeyParamSet(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    struct HksParamSet *paramSetOut)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    do {
        ret = BuildParamSetNotNull(paramSetIn, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSetIn not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcGetKeyParamSet(keyAlias, newParamSet, paramSetOut);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcGetKeyParamSet fail")

        struct HksBlob outBlob = { paramSetOut->paramSetSize, (uint8_t *)paramSetOut };
        inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + sizeof(paramSetOut->paramSetSize) +
            ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksGetKeyParamSetPack(keyAlias, newParamSet, &outBlob, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetKeyParamSetPack fail")

        ret = HksSendRequest(HKS_MSG_GET_KEY_PARAMSET, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksFreshParamSet(paramSetOut, false);
        HKS_IF_NOT_SUCC_LOGE(ret, "FreshParamSet fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    do {
        ret = BuildParamSetNotNull(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcKeyExist(keyAlias, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcKeyExist fail")

        inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksKeyExistPack(keyAlias, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksKeyExistPack fail")

        ret = HksSendRequest(HKS_MSG_KEY_EXIST, &inBlob, NULL, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientGenerateRandom(struct HksBlob *random, const struct HksParamSet *paramSet)
{
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(random), HKS_ERROR_INVALID_ARGUMENT)
    struct HksBlob inBlob = { sizeof(random->size), (uint8_t *)&(random->size) };
    return HksSendRequest(HKS_MSG_GENERATE_RANDOM, &inBlob, random, paramSet);
}

int32_t HksClientSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    int32_t ret = HksCheckBlob3AndParamSet(key, srcData, signature, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check in and out data failed")

    struct HksBlob tmpInData = *srcData;
    struct HksBlob tmpOutData = *signature;
    ret = HksSliceDataEntry(HKS_MSG_SIGN, key, paramSet, &tmpInData, &tmpOutData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksClientSign fail");
    } else {
        signature->size = tmpOutData.size;
    }
    return ret;
}

int32_t HksClientVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    int32_t ret = HksCheckBlob3AndParamSet(key, srcData, signature, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check in and out data failed")

    struct HksBlob tmpInData = *srcData;
    struct HksBlob tmpOutData = *signature;
    ret = HksSliceDataEntry(HKS_MSG_VERIFY, key, paramSet, &tmpInData, &tmpOutData);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksClientVerify fail")
    return ret;
}

static int32_t AddAeTag(struct HksParamSet *paramSet, const struct HksBlob *inText, bool isEncrypt)
{
    uint32_t aeadTagLen = HKS_AE_TAG_LEN;
    int32_t ret = HksGetAeadTagLengthWithoutMode(paramSet, &aeadTagLen);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    if (!isEncrypt) {
        HKS_IF_TRUE_LOGE_RETURN(inText->size <= aeadTagLen, HKS_ERROR_INVALID_ARGUMENT, "too small inText size")

        struct HksParam aeParam;
        aeParam.tag = HKS_TAG_AE_TAG;
        aeParam.blob.data = inText->data + inText->size - aeadTagLen;
        aeParam.blob.size = aeadTagLen;
        ret = HksAddParams(paramSet, &aeParam, 1);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "decrypt add ae params failed")
    }

    struct HksParam payloadParam;
    payloadParam.tag = HKS_TAG_PAYLOAD_LEN;
    payloadParam.uint32Param = inText->size;
    if (!isEncrypt) {
        payloadParam.uint32Param -= aeadTagLen;
    }
    ret = HksAddParams(paramSet, &payloadParam, 1);
    HKS_IF_NOT_SUCC_LOGE(ret, "add payload param failed")
    return ret;
}

static int32_t AddAesTag(const struct HksParamSet *paramSet, struct HksParamSet *newParamSet,
    struct HksBlob *inText, bool isEncrypt)
{
    bool isAeMode = false;
    bool isAes = false;
    int32_t ret = HksCheckAesAeMode(paramSet, &isAes, &isAeMode);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Except for AES GCM and CCM mode, no need add tag, return success */
    if ((!isAes) || (!isAeMode)) {
        return HKS_SUCCESS;
    }
    return AddAeTag(newParamSet, inText, isEncrypt);
}

static int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = HksInitParamSet(&newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append init operation param set fail")

    ret = HksAddParams(newParamSet, paramSet->params, paramSet->paramsCnt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append add in params fail");
        HksFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

static int32_t AppendCipherTag(const struct HksParamSet *paramSet, const struct HksBlob *inText, bool isEncrypt,
    struct HksParamSet **outParamSet)
{
    struct HksParamSet *newParamSet = NULL;
    int32_t ret = AppendToNewParamSet(paramSet, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "append cipher client service tag fail")

    do {
        ret = AddAesTag(paramSet, newParamSet, (struct HksBlob *)inText, isEncrypt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append add Aes Tag fail")

        ret = HksBuildParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE(ret, "append build paramset fail")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;
    return HKS_SUCCESS;
}

int32_t HksClientEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    int32_t ret = HksCheckBlob3AndParamSet(key, plainText, cipherText, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check in and out data failed")

    struct HksParamSet *newParamSet = NULL;
    ret = AppendCipherTag(paramSet, plainText, true, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "AppendCipherTag fail, ret = %" LOG_PUBLIC "d", ret)

    struct HksBlob tmpInData = *plainText;
    struct HksBlob tmpOutData = *cipherText;
    ret = HksSliceDataEntry(HKS_MSG_ENCRYPT, key, newParamSet, &tmpInData, &tmpOutData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksClientEncrypt fail");
    } else {
        cipherText->size = tmpOutData.size;
    }

    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksClientDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    int32_t ret = HksCheckBlob3AndParamSet(key, plainText, cipherText, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check in and out data failed")

    struct HksParamSet *newParamSet = NULL;
    struct HksBlob tmpCipherText = *cipherText;
    ret = AppendCipherTag(paramSet, &tmpCipherText, false, &newParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "AppendCipherTag fail, ret = %" LOG_PUBLIC "d", ret)

    struct HksBlob tmpOutData = *plainText;
    ret = HksSliceDataEntry(HKS_MSG_DECRYPT, key, newParamSet, &tmpCipherText, &tmpOutData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksClientDecrypt fail");
    } else {
        plainText->size = tmpOutData.size;
    }

    HksFreeParamSet(&newParamSet);
    return ret;
}

int32_t HksClientAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    int32_t ret = HksCheckIpcAgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcAgreeKey fail")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = ALIGN_SIZE(paramSet->paramSetSize) + sizeof(privateKey->size) + ALIGN_SIZE(privateKey->size) +
        sizeof(peerPublicKey->size) + ALIGN_SIZE(peerPublicKey->size) + sizeof(agreedKey->size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = HksAgreeKeyPack(&inBlob, paramSet, privateKey, peerPublicKey, agreedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAgreeKeyPack fail")

        ret = HksSendRequest(HKS_MSG_AGREE_KEY, &inBlob, agreedKey, paramSet);
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey)
{
    int32_t ret = HksCheckIpcDeriveKey(paramSet, mainKey, derivedKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcDeriveKey fail")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = ALIGN_SIZE(paramSet->paramSetSize) + sizeof(mainKey->size) + ALIGN_SIZE(mainKey->size) +
        sizeof(derivedKey->size);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = HksDeriveKeyPack(&inBlob, paramSet, mainKey, derivedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksDeriveKeyPack fail")

        ret = HksSendRequest(HKS_MSG_DERIVE_KEY, &inBlob, derivedKey, paramSet);
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientMac(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *mac)
{
    int32_t ret = HksCheckBlob3AndParamSet(key, srcData, mac, paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check in and out data failed")

    struct HksBlob tmpInData = *srcData;
    struct HksBlob tmpOutData = *mac;
    ret = HksSliceDataEntry(HKS_MSG_MAC, key, paramSet, &tmpInData, &tmpOutData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksClientMac fail");
    } else {
        mac->size = tmpOutData.size;
    }
    return ret;
}

int32_t HksClientGetKeyInfoList(const struct HksParamSet *paramSet, struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };
    do {
        ret = BuildParamSetNotNull(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcGetKeyInfoList(keyInfoList, newParamSet, *listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcGetKeyInfoList fail")

        inBlob.size = sizeof(*listCount) + (sizeof(keyInfoList->alias.size) +
            sizeof(keyInfoList->paramSet->paramSetSize)) * (*listCount) + ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        outBlob.size += sizeof(*listCount);
        for (uint32_t i = 0; i < *listCount; ++i) {
            outBlob.size += sizeof(keyInfoList[i].alias.size) + ALIGN_SIZE(keyInfoList[i].alias.size) +
                ALIGN_SIZE(keyInfoList[i].paramSet->paramSetSize);
        }

        outBlob.data = (uint8_t *)HksMalloc(outBlob.size);
        if (outBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = HksGetKeyInfoListPack(newParamSet, keyInfoList, &inBlob, *listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksGetKeyInfoListPack fail")

        ret = HksSendRequest(HKS_MSG_GET_KEY_INFO_LIST, &inBlob, &outBlob, newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest result is fail, ret = %" LOG_PUBLIC "d", ret)

        ret = HksGetKeyInfoListUnpackFromService(&outBlob, listCount, keyInfoList);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);
    return ret;
}

static int32_t CertificateChainInitBlob(struct HksBlob *inBlob, struct HksBlob *outBlob, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksCertChain *certChain)
{
    int32_t ret = HksCheckIpcCertificateChain(keyAlias, paramSet, certChain);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcCertificateChain fail")

    uint32_t certBufSize = sizeof(certChain->certsCount);
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        certBufSize += sizeof(certChain->certs[i].size) + ALIGN_SIZE(certChain->certs[i].size);
    }

    inBlob->size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(paramSet->paramSetSize) +
        sizeof(certBufSize);
    inBlob->data = (uint8_t *)HksMalloc(inBlob->size);
    HKS_IF_NULL_RETURN(inBlob->data, HKS_ERROR_MALLOC_FAIL)

    outBlob->size = certBufSize;
    outBlob->data = (uint8_t *)HksMalloc(certBufSize);
    if (outBlob->data == NULL) {
        HKS_FREE_BLOB(*inBlob);
        return HKS_ERROR_MALLOC_FAIL;
    }

    return HKS_SUCCESS;
}

int32_t HksClientAttestKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain, bool needAnonCertChain)
{
    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };

    int32_t ret = 0;
    do {
        ret = CertificateChainInitBlob(&inBlob, &outBlob, keyAlias, paramSet, certChain);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CertificateChainInitBlob fail")
        struct HksParam *isBase64Param = NULL;
        bool isBase64 = false;
        ret = HksGetParam(paramSet, HKS_TAG_ATTESTATION_BASE64, &isBase64Param);
        if (ret == HKS_SUCCESS) {
            isBase64 = isBase64Param->boolParam;
        }
        ret = HksCertificateChainPack(&inBlob, keyAlias, paramSet, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCertificateChainPack fail")

        if (needAnonCertChain) {
            ret = HksSendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, &inBlob, &outBlob, paramSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CertificateChainGetOrAnonAttest request fail")
        } else {
            ret = HksSendRequest(HKS_MSG_ATTEST_KEY, &inBlob, &outBlob, paramSet);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CertificateChainGetOrAttest request fail")
        }

        ret = HksCertificateChainUnpackFromService(&outBlob, isBase64, certChain);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CertificateChainUnpackFromService fail")
    } while (0);

    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);
    return ret;
}

static int32_t CopyData(const uint8_t *data, const uint32_t size, struct HksBlob *out)
{
    if (size == 0) {
        out->size = 0;
        return HKS_SUCCESS;
    }

    HKS_IF_TRUE_LOGE_RETURN(out->size < size, HKS_ERROR_BUFFER_TOO_SMALL,
        "out size[%" LOG_PUBLIC "u] smaller than [%" LOG_PUBLIC "u]", out->size, size)
    (void)memcpy_s(out->data, out->size, data, size);
    out->size = size;
    return HKS_SUCCESS;
}

static int32_t ClientInit(const struct HksBlob *inData, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    uint8_t *tmpOut = (uint8_t *)HksMalloc(HANDLE_SIZE + TOKEN_SIZE);
    HKS_IF_NULL_LOGE_RETURN(tmpOut, HKS_ERROR_MALLOC_FAIL, "malloc ipc tmp out failed")
    struct HksBlob outBlob = { HANDLE_SIZE + TOKEN_SIZE, tmpOut };

    int32_t ret;
    do {
        ret = HksSendRequest(HKS_MSG_INIT, inData, &outBlob, paramSet);
        if (ret == HKS_ERROR_IPC_MSG_FAIL) {
            ret = HksSendRequest(HKS_MSG_INIT, inData, &outBlob, paramSet);
        }
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "client init send fail")

        if (outBlob.size < HANDLE_SIZE) {
            HKS_LOG_E("invalid out size[%" LOG_PUBLIC "u]", outBlob.size);
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }
        ret = CopyData(outBlob.data, HANDLE_SIZE, handle);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy handle failed")

        if (token != NULL) {
            if (outBlob.size < (HANDLE_SIZE + TOKEN_SIZE)) {
                HKS_LOG_D("client init success without out token");
                token->size = 0;
                break;
            }
            if (token->size < TOKEN_SIZE) {
                HKS_LOG_E("copy token failed");
                ret = HKS_ERROR_BUFFER_TOO_SMALL;
                break;
            }

            ret = CopyData(outBlob.data + HANDLE_SIZE, TOKEN_SIZE, token);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy token failed")
        }
    } while (0);

    HKS_FREE(tmpOut);
    return ret;
}

int32_t HksClientInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    struct HksParamSet *sendParamSet = NULL;

    struct HksParam params[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER,
          .blob = *keyAlias },
        { .tag = HKS_TAG_PARAM1_BUFFER,
          .blob = { paramSet->paramSetSize,
                    (uint8_t *)paramSet } },
    };

    int32_t ret = HksParamsToParamSet(params, HKS_ARRAY_SIZE(params), &sendParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksParamsToParamSet fail")

    struct HksBlob parcelBlob = {
        .size = sendParamSet->paramSetSize,
        .data = (uint8_t *)sendParamSet
    };

    ret = ClientInit(&parcelBlob, paramSet, handle, token);
    HksFreeParamSet(&sendParamSet);
    return ret;
}

int32_t HksClientUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksParamSet *sendParamSet = NULL;
    struct HksParam updateParams[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER,
          .blob = { paramSet->paramSetSize,
                    (uint8_t *)paramSet } },
        { .tag = HKS_TAG_PARAM1_BUFFER,
          .blob = *handle },
        { .tag = HKS_TAG_PARAM2_BUFFER,
          .blob = *inData },
    };

    int32_t ret = HksParamsToParamSet(updateParams, HKS_ARRAY_SIZE(updateParams), &sendParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksParamSetPack fail")

    struct HksBlob parcelBlob = {
        .size = sendParamSet->paramSetSize,
        .data = (uint8_t *)sendParamSet
    };
    ret = HksSendRequest(HKS_MSG_UPDATE, &parcelBlob, outData, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksParamSet send fail, ret = %" LOG_PUBLIC "d", ret);
        HksFreeParamSet(&sendParamSet);
        return ret;
    }

    HksFreeParamSet(&sendParamSet);
    return ret;
}

int32_t HksClientFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksParamSet *sendParamSet = NULL;
    struct HksParam finishParams[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER,
          .blob = { paramSet->paramSetSize,
                    (uint8_t *)paramSet } },
        { .tag = HKS_TAG_PARAM1_BUFFER,
          .blob = *handle },
        { .tag = HKS_TAG_PARAM2_BUFFER,
          .blob = *inData },
    };

    int32_t ret = HksParamsToParamSet(finishParams, HKS_ARRAY_SIZE(finishParams), &sendParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksParamSetPack fail")

    struct HksBlob parcelBlob = {
        .size = sendParamSet->paramSetSize,
        .data = (uint8_t *)sendParamSet
    };
    ret = HksSendRequest(HKS_MSG_FINISH, &parcelBlob, outData, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksParamSet send fail, ret = %" LOG_PUBLIC "d", ret);
        HksFreeParamSet(&sendParamSet);
        return ret;
    }

    HksFreeParamSet(&sendParamSet);
    return ret;
}

int32_t HksClientAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    struct HksParamSet *sendParamSet = NULL;
    struct HksParam params[] = {
        { .tag = HKS_TAG_PARAM0_BUFFER,
          .blob = { paramSet->paramSetSize,
                    (uint8_t *)paramSet } },
        { .tag = HKS_TAG_PARAM1_BUFFER,
          .blob = *handle },
    };

    int32_t ret = HksParamsToParamSet(params, HKS_ARRAY_SIZE(params), &sendParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksParamSetPack fail")

    struct HksBlob parcelBlob = {
        .size = sendParamSet->paramSetSize,
        .data = (uint8_t *)sendParamSet
    };
    ret = HksSendRequest(HKS_MSG_ABORT, &parcelBlob, NULL, paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksParamSet send fail, ret = %" LOG_PUBLIC "d", ret);
        HksFreeParamSet(&sendParamSet);
        return ret;
    }

    HksFreeParamSet(&sendParamSet);
    return ret;
}

static int32_t ListAliasesInitBlob(const struct HksParamSet *paramSet,
    struct HksBlob *inBlob, struct HksBlob *outBlob)
{
    inBlob->size = ALIGN_SIZE(paramSet->paramSetSize);
    inBlob->data = (uint8_t *)HksMalloc(inBlob->size);
    HKS_IF_NULL_RETURN(inBlob->data, HKS_ERROR_MALLOC_FAIL)

    outBlob->size = sizeof(HKS_MAX_KEY_ALIAS_COUNT) + (HKS_MAX_KEY_ALIAS_COUNT * HKS_MAX_KEY_ALIAS_LEN);
    outBlob->data = (uint8_t *)HksMalloc(outBlob->size);
    if (outBlob->data == NULL) {
        HKS_LOG_E("HksMalloc outBlob fail");
        HKS_FREE_BLOB(*inBlob);
        return HKS_ERROR_MALLOC_FAIL;
    }
    return HKS_SUCCESS;
}

int32_t HksClientListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData)
{
    int32_t ret;
    struct HksBlob inBlob = { 0, NULL };
    struct HksBlob outBlob = { 0, NULL };
    do {
        ret = HksCheckIpcListAliases(paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcListAliases fail")

        ret = ListAliasesInitBlob(paramSet, &inBlob, &outBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ListAliasesInitBlob fail")

        ret = HksListAliasesPack(paramSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksListAliasesPack fail")

        ret = HksSendRequest(HKS_MSG_LIST_ALIASES, &inBlob, &outBlob, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret);

        ret = HksListAliasesUnpackFromService(&outBlob, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksListAliasesUnpackFromService fail")
    } while (0);

    HKS_IF_NOT_SUCC_LOGE(ret, "HksClientListAliases fail, ret = %" LOG_PUBLIC "d", ret)

    HKS_FREE_BLOB(inBlob);
    HKS_FREE_BLOB(outBlob);
    return ret;
}

int32_t HksClientRenameKeyAlias(const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;
    struct HksBlob inBlob = { 0, NULL };

    do {
        ret = BuildParamSetNotNull(paramSet, &newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ensure paramSet not null failed, ret = %" LOG_PUBLIC "d", ret)

        ret = HksCheckIpcRenameKeyAlias(oldKeyAlias, newParamSet, newKeyAlias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCheckIpcRenameKeyAlias failed!")

        inBlob.size = sizeof(oldKeyAlias->size) + ALIGN_SIZE(oldKeyAlias->size) +
            sizeof(newKeyAlias->size) + ALIGN_SIZE(newKeyAlias->size) +
            ALIGN_SIZE(newParamSet->paramSetSize);
        inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
        if (inBlob.data == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        ret = HksRenameKeyAliasPack(oldKeyAlias, newKeyAlias, newParamSet, &inBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksRenameKeyAliasPack failed!")
        ret = HksSendRequest(HKS_MSG_RENAME_KEY_ALIAS, &inBlob, NULL, newParamSet);
    } while (0);

    HksFreeParamSet(&newParamSet);
    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientChangeStorageLevel(const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *destParamSet)
{
    int32_t ret = HksCheckIpcChangeStorageLevel(keyAlias, srcParamSet, destParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcChangeStorageLevel fail")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) + ALIGN_SIZE(srcParamSet->paramSetSize) +
        ALIGN_SIZE(destParamSet->paramSetSize);
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL)

    do {
        ret = HksChangeStorageLevelPack(&inBlob, keyAlias, srcParamSet, destParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksChangeStorageLevelPack fail")

        ret = HksSendRequest(HKS_MSG_CHANGE_STORAGE_LEVEL, &inBlob, NULL, srcParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientWrapKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *wrappedKey)
{
    int32_t ret = HksCheckIpcWrapKey(keyAlias, paramSet, wrappedKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcWrapKey fail.")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
                  ALIGN_SIZE(paramSet->paramSetSize) + sizeof(wrappedKey->size);
    
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_LOGE_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL, "malloc inblob data fail")

    do {
        ret = HksWrapKeyPack(&inBlob, keyAlias, paramSet, wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksWrapKeyPack fail.")

        ret = HksSendRequest(HKS_MSG_WRAP_KEY, &inBlob, wrappedKey, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}

int32_t HksClientUnwrapKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *wrappedKey)
{
    int32_t ret = HksCheckIpcUnwrapKey(keyAlias, paramSet, wrappedKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckIpcUnwrapKey fail.")

    struct HksBlob inBlob = { 0, NULL };
    inBlob.size = sizeof(keyAlias->size) + ALIGN_SIZE(keyAlias->size) +
                  ALIGN_SIZE(paramSet->paramSetSize) + sizeof(wrappedKey->size) + ALIGN_SIZE(wrappedKey->size);
    
    inBlob.data = (uint8_t *)HksMalloc(inBlob.size);
    HKS_IF_NULL_LOGE_RETURN(inBlob.data, HKS_ERROR_MALLOC_FAIL, "malloc inblob data fail")

    do {
        ret = HksUnwrapKeyPack(&inBlob, keyAlias, paramSet, wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksUnwrapKeyPack fail.")

        ret = HksSendRequest(HKS_MSG_UNWRAP_KEY, &inBlob, NULL, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksSendRequest fail, ret = %" LOG_PUBLIC "d", ret)
    } while (0);

    HKS_FREE_BLOB(inBlob);
    return ret;
}
