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

#include "hks_ukey_service_provider_adapter.h"
#include "hks_ukey_service_provider.h"
#include "hks_ukey_common.h"
#include "hks_sa_interface.h"
#include "hks_type.h"
#include "securec.h"

#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

static int32_t HksIpcCheckBlob(const struct HksBlob *blob, uint32_t minSize, uint32_t maxSize)
{
    if (blob == nullptr || blob->data == nullptr || blob->size < minSize || blob->size > maxSize) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(name, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcProviderRegAdapter invalid name blob")

    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderRegister(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(name, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcProviderUnregAdapter invalid name blob")
    
    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderUnRegister(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcCreateRemKeyHandleAdapter invalid resourceId blob")
    
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    std::string remoteHandle;
    ret = OHOS::Security::Huks::HksIpcServiceOnCreateRemoteKeyHandle(processInfo, cppresourceId, cppParamSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnCreateRemoteKeyHandle fail")
    return ret;
}

int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcCloseRemKeyHandleAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceOnCloseRemoteKeyHandle(processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet)
{
    int32_t ret = HksIpcCheckBlob(providerName, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportProvCertsAdapter invalid providerName blob")

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
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportCertAdapter invalid resourceId blob")

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
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcAuthUkeyPinAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);
    return OHOS::Security::Huks::HksIpcServiceOnAuthUkeyPin(processInfo, cppresourceId, cppParamSet,
        *outStatus, *retryCount);
}

int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet, int32_t *outStatus)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcGetUkeyPinAuthStateAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);
    return OHOS::Security::Huks::HksIpcServiceOnGetVerifyPinStatus(processInfo, cppresourceId, cppParamSet, *outStatus);
}

int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcClearPinStatusAdapter invalid resourceId blob")

    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    return OHOS::Security::Huks::HksIpcServiceOnClearUkeyPinAuthStatus(processInfo, cppResourceId);
}

static int32_t RemotePropertyPack(const CppParamSet &cppParamSet,
    std::unique_ptr<uint8_t[]> &replyData, uint32_t &replySize, int32_t returnResult)
{
    int32_t ret = 0;
    replySize = 0;
    const HksParamSet *hksParamSet = cppParamSet.GetParamSet();

    do {
        uint32_t resultSize = ALIGN_SIZE(sizeof(returnResult));
        uint32_t paramSetSize = 0;
        uint32_t totalSize = resultSize;

        if (hksParamSet != nullptr) {
            paramSetSize = ALIGN_SIZE(hksParamSet->paramSetSize);
            totalSize += paramSetSize;
        }

        HKS_IF_TRUE_LOGE_BREAK(totalSize == 0 || totalSize > MAX_OUT_BLOB_SIZE,
            "invalid totalSize %" LOG_PUBLIC "u", totalSize);

        auto tmp = std::make_unique<uint8_t[]>(totalSize);
        HKS_IF_NULL_LOGE_BREAK(tmp, "alloc replyData failed")

        ret = memcpy_s(tmp.get(), totalSize, &returnResult, sizeof(returnResult));
        HKS_IF_NOT_EOK_LOGE_BREAK(ret, "memcpy_s returnResult failed")

        if (hksParamSet != nullptr) {
            ret = memcpy_s(tmp.get() + resultSize, totalSize - resultSize,
                hksParamSet, hksParamSet->paramSetSize);
            HKS_IF_NOT_EOK_LOGE_BREAK(ret, "memcpy_s hksParamSet failed")
        }

        replySize = totalSize;
        replyData = std::move(tmp);
    } while (0);

    return ret;
}

int32_t HksIpcServiceOnGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSet, const uint8_t *remoteObject)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnGetRemotePropertyAdapter invalid resourceId blob")

    ret = HksIpcCheckBlob(propertyId, 1, HKS_EXT_MAX_PROPERTY_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcServiceOnGetRemotePropertyAdapter invalid propertyId blob")

    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string cppPropertyId(reinterpret_cast<const char*>(propertyId->data), propertyId->size);
    CppParamSet cppParamSet(paramSet);
    CppParamSet cppOutParams;

    auto hksExtProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));
    HKS_IF_NULL_LOGE_RETURN(hksExtProxy, HKS_ERROR_NULL_POINTER, "hksExtProxy is null");

    ret = OHOS::Security::Huks::HksIpcServiceOnGetRemoteProperty(processInfo, cppResourceId,
        cppPropertyId, cppParamSet, cppOutParams);
    HKS_IF_NOT_SUCC_LOGE(ret, "HksIpcServiceOnGetRemoteProperty fail. ret = %" LOG_PUBLIC "d", ret);
    
    std::unique_ptr<uint8_t[]> outData;
    uint32_t outSize = 0;
    ret = RemotePropertyPack(cppOutParams, outData, outSize, ret);
    HKS_IF_NOT_SUCC_LOGE(ret, "PackRemoteProperty fail");

    hksExtProxy->SendAsyncReply(HKS_SUCCESS, outData, outSize, HKS_MSG_EXT_GET_REMOTE_PROPERTY_REPLY);
    return HKS_SUCCESS;
}

int32_t HksServiceOnUkeyImportWrappedKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    std::string cppIndex(reinterpret_cast<const char*>(keyAlias->data), keyAlias->size);
    std::string cppWrappingKeyIndex(reinterpret_cast<const char*>(wrappingKeyAlias->data), wrappingKeyAlias->size);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> wrappedData;
    if (wrappedKeyData != nullptr && wrappedKeyData->data != nullptr && wrappedKeyData->size != 0) {
        wrappedData.assign(wrappedKeyData->data, wrappedKeyData->data + wrappedKeyData->size);
    }

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    int32_t ret = pluginManager->OnImportWrappedKey(*processInfo, cppIndex, cppWrappingKeyIndex, cppParamSet, wrappedData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnImportWrappedKey fail. ret: %" LOG_PUBLIC "d", ret)
    
    return ret;
}

int32_t HksServiceOnUkeyExportPublicKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    std::string cppIndex(reinterpret_cast<const char*>(keyAlias->data), keyAlias->size);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> outdata;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    int32_t ret = pluginManager->OnExportPublicKey(*processInfo, cppIndex, cppParamSet, outdata);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnExportPublicKey fail. ret: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGI_RETURN(key == nullptr, ret, "key is nullptr. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(key->size == 0, ret, "key size is 0. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(key->data == nullptr, ret, "key data is nullptr. ret: %" LOG_PUBLIC "d", ret);
    if (key->size < static_cast<uint32_t>(outdata.size())) {
        HKS_LOG_E("exportPublicKey key size too small. size: %" LOG_PUBLIC "u. needSize: %" LOG_PUBLIC "zu",
        key->size, outdata.size());
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = memcpy_s(key->data, key->size, outdata.data(), outdata.size());
    if (ret != EOK) {
        HKS_LOG_E("memcpy in HksServiceOnUkeyExportPublicKey fail. ret:: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_COPY_FAIL;
    }
    key->size = static_cast<uint32_t>(outdata.size());
    return ret;
}

#ifdef __cplusplus
}
#endif