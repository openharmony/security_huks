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

#include "hks_ipc_service_provider_adapter.h"
#include "hks_ipc_service_provider.h"
#include "hks_ukey_common.h"
#include "hks_sa_interface.h"
#include "securec.h"

#include <string>
#include <vector>

// 适配器模式
int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderRegister(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderUnRegister(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut)
{
    int32_t ret;
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    std::string remoteHandle;
    ret = OHOS::Security::Huks::HksIpcServiceOnCreateRemoteKeyHandle(processInfo, cppresourceId,
        cppParamSet, remoteHandle);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnCreateRemoteKeyHandle fail")

    uint32_t copyLen = static_cast<uint32_t>(remoteHandle.size());
    if (copyLen > static_cast<uint32_t>(MAX_OUT_BLOB_SIZE)) {
        HKS_LOG_E("remoteHandle size is too large");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    remoteHandleOut->size = copyLen;
    memcpy_s(remoteHandleOut->data, remoteHandleOut->size, remoteHandle.data(), copyLen);

    return ret;
}

int32_t HksIpcGetRemoteHandleAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut)
{
    int32_t ret;
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    std::string remoteHandle;
    ret = OHOS::Security::Huks::HksIpcServiceOnFindRemoteKeyHandle(processInfo, cppresourceId,
        cppParamSet, remoteHandle);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnSigned fail")

    uint32_t copyLen = static_cast<uint32_t>(remoteHandle.size());
    if (copyLen > static_cast<uint32_t>(MAX_OUT_BLOB_SIZE)) {
        HKS_LOG_E("remoteHandle size is too large");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    remoteHandleOut->size = copyLen;
    memcpy_s(remoteHandleOut->data, remoteHandleOut->size, remoteHandle.data(), copyLen);

    return ret;
}

int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet)
{
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceOnCloseRemoteKeyHandle(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcSignAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *resourceId, const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
    int32_t ret;
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string cppSrcData(reinterpret_cast<const char*>(srcData->data), srcData->size);
    CppParamSet cppParamSet(paramSet);

    std::string signature;
    ret = OHOS::Security::Huks::HksIpcServiceOnSigned(processInfo, cppresourceId, cppParamSet, cppSrcData, signature);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnSigned fail")

    uint32_t copyLen = std::min(signatureOut->size, static_cast<uint32_t>(signature.size()));
    memcpy_s(signatureOut->data, signatureOut->size, signature.data(), copyLen);
    signatureOut->size = copyLen;

    return ret;
}

int32_t HksIpcVerifyAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *resourceId, const struct HksBlob *data, struct HksBlob *signatureOut)
{
    int32_t ret;
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string cppData(reinterpret_cast<const char*>(data->data), data->size);
    CppParamSet cppParamSet(paramSet);

    std::string signature;
    ret = OHOS::Security::Huks::HksIpcServiceOnVerify(processInfo, cppresourceId, cppParamSet, cppData, signature);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnSigned fail")

    uint32_t copyLen = std::min(signatureOut->size, static_cast<uint32_t>(signature.size()));
    memcpy_s(signatureOut->data, signatureOut->size, signature.data(), copyLen);
    signatureOut->size = copyLen;

    return ret;
}

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet)
{
    int32_t ret = 0;
    std::string cppProviderName(reinterpret_cast<const char*>(providerName->data), providerName->size);
    std::string certificates;
    CppParamSet cppParamSet(paramSet);

    ret = OHOS::Security::Huks::HksIpcServiceOnExportProviderAllCertificates(processInfo, cppProviderName,
        cppParamSet, certificates);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportProvCertsAdapter fail")

    ret = OHOS::Security::Huks::JsonArrayToCertInfoSet(certificates, *certInfoSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail")

    return ret;
}

int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet)
{
    int32_t ret = 0;
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string certificates;
    CppParamSet cppParamSet(paramSet);

    ret = OHOS::Security::Huks::HksIpcServiceOnExportCertificate(processInfo, cppresourceId, cppParamSet, certificates);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnFindresourceIdCertificate fail")

    ret = OHOS::Security::Huks::JsonArrayToCertInfoSet(certificates, *certInfoSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail")

    return ret;
}

int32_t HksIpcAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet, int32_t *outStatus, uint32_t *retryCount)
{
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);
    return OHOS::Security::Huks::HksIpcServiceOnAuthUkeyPin(processInfo, cppresourceId, cppParamSet,
        *outStatus, *retryCount);
}

int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet, int32_t *outStatus)
{
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);
    return OHOS::Security::Huks::HksIpcServiceOnGetVerifyPinStatus(processInfo, cppresourceId, cppParamSet, *outStatus);
}

int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId)
{
    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    return OHOS::Security::Huks::HksIpcServiceOnClearUkeyPinAuthStatus(processInfo, cppResourceId);
}

static int32_t RemotePropertyPack(const CppParamSet &cppParamSet,
    std::unique_ptr<uint8_t[]> &replyData, uint32_t &replySize)
{
    replySize = 0;
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();
    HKS_IF_NULL_LOGE_RETURN(hksParamSet, HKS_ERROR_NULL_POINTER, "paramSet null");

    HksBlob outBlob { ALIGN_SIZE(hksParamSet->paramSetSize), nullptr };
    int32_t ret = 0;
    do {
        HKS_IF_TRUE_LOGE_BREAK(outBlob.size == 0 || outBlob.size > MAX_OUT_BLOB_SIZE,
            "invalid outBlob.size %" LOG_PUBLIC "u", outBlob.size);

        outBlob.data = (uint8_t *)HksMalloc(outBlob.size);
        HKS_IF_NULL_LOGE_BREAK(outBlob.data, "malloc outBlob.data failed")

        ret = HksParamSetPack(&outBlob, hksParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksParamSetPack fail %" LOG_PUBLIC "d", ret)

        auto tmp = std::make_unique<uint8_t[]>(outBlob.size);
        HKS_IF_NULL_LOGE_BREAK(tmp, "alloc replyData failed")

        HKS_IF_NOT_EOK_LOGE_BREAK(memcpy_s(tmp.get(), outBlob.size, outBlob.data, outBlob.size),
            "memcpy_s replyData failed")

        replySize = outBlob.size;
        replyData = std::move(tmp);
    } while (0);

    HKS_FREE_BLOB(outBlob);
    return ret;
}

int32_t HksIpcServiceOnGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSet, const uint8_t *remoteObject)
{
    int32_t ret = 0;
    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string cppPropertyId(reinterpret_cast<const char*>(propertyId->data), propertyId->size);
    CppParamSet cppParamSet(paramSet);
    CppParamSet cppOutParams;

    auto hksExtProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));

    ret = OHOS::Security::Huks::HksIpcServiceOnGetRemoteProperty(processInfo, cppResourceId,
        cppPropertyId, cppParamSet, cppOutParams);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail");
    HKS_IF_NULL_LOGE_RETURN(hksExtProxy, HKS_ERROR_NULL_POINTER, "hksExtProxy is null");

    std::unique_ptr<uint8_t[]> outData;
    uint32_t outSize = 0;
    ret = RemotePropertyPack(cppOutParams, outData, outSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "PackRemoteProperty fail");

    hksExtProxy->SendAsyncReply(HKS_SUCCESS, outData, outSize, HKS_MSG_EXT_GET_REMOTE_PROPERTY_REPLY);
    return HKS_SUCCESS;
}