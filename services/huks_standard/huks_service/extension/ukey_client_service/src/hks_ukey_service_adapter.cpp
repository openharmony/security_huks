/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_ukey_service_adapter.h"
#include "hks_template.h"
#include "hks_ukey_common.h"
#include "hks_cpp_abilityinfo.h"
#include "hks_sa_interface.h"
#include "hks_type.h"
#include "hks_external_error_info.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_common_check.h"
#include "hks_report_ukey_event.h"
#include "securec.h"
#include <cstdint>
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

constexpr uint32_t MAX_SESSION_INDEX_SIZE = 1024;

int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(name, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcProviderRegAdapter invalid name blob")

    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->RegisterProvider(*processInfo, cppresourceId, cppParamSet);
}

int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *name,
    const struct HksParamSet *paramSet)
{
    int32_t ret = HksIpcCheckBlob(name, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcProviderUnregAdapter invalid name blob")

    std::string cppresourceId(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    bool isDeath = false;
    return pluginManager->UnRegisterProvider(*processInfo, cppresourceId, cppParamSet, isDeath);
}

int32_t HksIpcQueryAbilityInfoAdapter(const struct HksProcessInfo *processInfo, struct HksBlob *resourceId,
    HksAbilityInfo *abilityInfo)
{
    int32_t ret = HksIpcCheckBlob(&abilityInfo->abilityName, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "invalid abilityName blob")

    ret = HksIpcCheckBlob(&abilityInfo->bundleName, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "invalid bundleName blob")

    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppAbilityInfo cppAbilityInfo(abilityInfo);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnQueryAbility(*processInfo, cppResourceId, cppAbilityInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "OnQueryAbility fail")

    HKS_IF_TRUE_LOGE_RETURN(abilityInfo->abilityName.size < cppAbilityInfo.abilityName.size(),
        HKS_ERROR_INSUFFICIENT_MEMORY,
        "cppAbilityInfo.abilityName is too long, size: %" LOG_PUBLIC "zu", cppAbilityInfo.abilityName.size())
    ret = memcpy_s(abilityInfo->abilityName.data, abilityInfo->abilityName.size,
        cppAbilityInfo.abilityName.data(), cppAbilityInfo.abilityName.size());
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INSUFFICIENT_MEMORY, "copy ability name fail")
    abilityInfo->abilityName.size = cppAbilityInfo.abilityName.size();

    HKS_IF_TRUE_LOGE_RETURN(abilityInfo->bundleName.size < cppAbilityInfo.bundleName.size(),
        HKS_ERROR_INSUFFICIENT_MEMORY,
        "cppAbilityInfo.bundleName is too long, size: %" LOG_PUBLIC "zu", cppAbilityInfo.bundleName.size())
    ret = memcpy_s(abilityInfo->bundleName.data, abilityInfo->bundleName.size,
        cppAbilityInfo.bundleName.data(), cppAbilityInfo.bundleName.size());
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INSUFFICIENT_MEMORY, "copy bundle name fail")
    abilityInfo->bundleName.size = cppAbilityInfo.bundleName.size();

    (void)memset_s(resourceId->data, resourceId->size, 0, resourceId->size);
    HKS_IF_TRUE_LOGE_RETURN(resourceId->size < cppResourceId.size(), HKS_ERROR_INSUFFICIENT_MEMORY,
        "cppResourceId is too long, size: %" LOG_PUBLIC "zu", cppResourceId.size())
    ret = memcpy_s(resourceId->data, resourceId->size, cppResourceId.data(), cppResourceId.size());
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INSUFFICIENT_MEMORY, "copy resourceId fail")
    resourceId->size = cppResourceId.size();

    return ret;
}

int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcCreateRemKeyHandleAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnCreateRemoteKeyHandle(*processInfo, cppresourceId, cppParamSet, errInfo);
}

int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcCloseRemKeyHandleAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnCloseRemoteKeyHandle(*processInfo, cppresourceId, cppParamSet, errInfo);
}

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet, struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(providerName, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportProvCertsAdapter invalid providerName blob")

    std::string cppProviderName(reinterpret_cast<const char*>(providerName->data), providerName->size);
    std::string certificates;
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnExportProviderAllCertificates(*processInfo, cppProviderName, cppParamSet,
        certificates, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportProvCertsAdapter fail")

    ret = OHOS::Security::Huks::JsonArrayToCertInfoSet(certificates, *certInfoSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail")

    return ret;
}

int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet, struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportCertAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    std::string certificates;
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnExportCertificate(*processInfo, cppresourceId, cppParamSet, certificates, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnExportCertificate fail")

    ret = OHOS::Security::Huks::JsonArrayToCertInfoSet(certificates, *certInfoSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail")

    return ret;
}

int32_t HksIpcImportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksExtCertInfo *certInfo, const struct HksParamSet *paramSet, struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcImportCertAdapter invalid resourceId blob")

    if (certInfo == nullptr || certInfo->index.data == nullptr || certInfo->cert.data == nullptr) {
        HKS_LOG_E("HksIpcImportCertAdapter invalid certInfo");
        return HKS_ERROR_NULL_POINTER;
    }

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnImportCertificate(*processInfo, cppresourceId, *certInfo, cppParamSet, errInfo);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnImportCertificate fail")

    return ret;
}

int32_t HksIpcAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    const struct HksParamSet *paramSet, struct HksExtAuthPinOutParam *authOutParam,
    struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcAuthUkeyPinAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnAuthUkeyPin(*processInfo, cppresourceId, cppParamSet, *authOutParam, errInfo);
}

int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet, int32_t *outStatus,
    struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcGetUkeyPinAuthStateAdapter invalid resourceId blob")

    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnGetVerifyPinStatus(*processInfo, cppresourceId, cppParamSet, *outStatus, errInfo);
}

int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId,
    struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcClearPinStatusAdapter invalid resourceId blob")

    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    return pluginManager->OnClearUkeyPinAuthStatus(*processInfo, cppResourceId, errInfo);
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

        HKS_IF_TRUE_BREAK(hksParamSet != nullptr && memcpy_s(tmp.get() + resultSize, totalSize - resultSize,
            hksParamSet, hksParamSet->paramSetSize) != EOK)

        replySize = totalSize;
        replyData = std::move(tmp);
    } while (0);

    return ret;
}

int32_t HksIpcServiceOnSetOrGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksExtPropertyOperationInfo *propertyInfo, const struct HksParamSet *paramSet,
    const uint8_t *remoteObject)
{
    int32_t ret = HksIpcCheckBlob(propertyInfo->resourceId, 1, HKS_EXT_MAX_RESOURCE_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "invalid resourceId blob")

    ret = HksIpcCheckBlob(propertyInfo->propertyId, 1, HKS_EXT_MAX_PROPERTY_ID_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "invalid propertyId blob")

    std::string resourceIdStr(reinterpret_cast<const char*>(propertyInfo->resourceId->data),
        propertyInfo->resourceId->size);
    std::string propertyIdStr(reinterpret_cast<const char*>(propertyInfo->propertyId->data),
        propertyInfo->propertyId->size);
    CppParamSet cppParamSet(paramSet);

    auto hksExtProxy = OHOS::iface_cast<OHOS::Security::Hks::IHksExtService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));
    HKS_IF_NULL_LOGE_RETURN(hksExtProxy, HKS_ERROR_NULL_POINTER, "hksExtProxy is null");

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnSetOrGetRemoteProperty(processAndError, propertyInfo->operation, resourceIdStr,
        propertyIdStr, cppParamSet);
    HKS_IF_NOT_SUCC_LOGE(ret, "OnSetOrGetRemoteProperty fail. ret = %" LOG_PUBLIC "d", ret);

    std::unique_ptr<uint8_t[]> outData;
    uint32_t outSize = 0;
    ret = RemotePropertyPack(cppParamSet, outData, outSize, ret);
    HKS_IF_NOT_SUCC_LOGE(ret, "PackRemoteProperty fail");

    hksExtProxy->SendAsyncReply(HKS_SUCCESS, outData, outSize,
        HKS_MSG_EXT_SET_OR_GET_REMOTE_PROPERTY_REPLY, processAndError.errInfo);

    HKS_IF_TRUE_EXCU(processAndError.errInfo != nullptr, HksFreeExternalErrorInfo(processAndError.errInfo));
    return HKS_SUCCESS;
}

int32_t HksIpcServiceOnGetResourceIdAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *providerName, const struct HksParamSet *paramSet, struct HksBlob *resourceId,
    struct HksExternalErrorInfo **errInfo)
{
    int32_t ret = HksIpcCheckBlob(providerName, 1, HKS_EXT_MAX_PROVIDER_NAME_LEN);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "HksIpcServiceOnGetResourceIdAdapter invalid providerName blob")

    std::string cppProviderName(reinterpret_cast<const char*>(providerName->data), providerName->size);
    CppParamSet cppParamSet(paramSet);

    std::string cppResourceId;
    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    ret = pluginManager->OnGetResourceId(*processInfo, cppProviderName, cppParamSet, cppResourceId, errInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "OnGetResourceId fail. ret = %" LOG_PUBLIC "d", ret);

    if (cppResourceId.size() > HKS_EXT_MAX_RESOURCE_ID_LEN) {
        HKS_LOG_E("cppResourceId too long, size: %" LOG_PUBLIC "zu", cppResourceId.size());
        return HKS_ERROR_INSUFFICIENT_DATA;
    }

    resourceId->size = static_cast<uint32_t>(cppResourceId.size());
    resourceId->data = static_cast<uint8_t*>(HksMalloc(resourceId->size));
    HKS_IF_NULL_RETURN(resourceId->data, HKS_ERROR_MALLOC_FAIL)

    (void)memcpy_s(resourceId->data, resourceId->size, cppResourceId.c_str(), cppResourceId.size());

    return HKS_SUCCESS;
}

int32_t HksServiceOnUkeyGenerateKey(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckBlob2(&processInfo->processName, resourceId);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Hks check processName or resourceId fail. ret: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(resourceId->size > MAX_SESSION_INDEX_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "resourceId size too large. size: %" LOG_PUBLIC "d. maxSize: %" LOG_PUBLIC "d",
        resourceId->size, MAX_SESSION_INDEX_SIZE)
    std::string cppResourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    CppParamSet cppParamSet(paramSet);

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    ret = pluginManager->OnGenerateKey(processAndError, cppResourceId, cppParamSet);
    HKS_IF_TRUE_RETURN(ret == HKS_SUCCESS, HKS_SUCCESS)
    HKS_LOG_E("OnGenerateKey fail. ret: %" LOG_PUBLIC "d", ret);
    HksClearThreadExtErrMsg();
    int32_t errVal = 0;
    if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
        errVal = processAndError.errInfo->errVal;
        HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
    }
    HksFreeExternalErrorInfo(processAndError.errInfo);
    struct UKeyReportErrInfo reportErr = { ret, errVal };
    ReportUKeyKeyEvent(HKS_EVENT_UKEY_GENERATE_KEY, &reportErr, processInfo, paramSet);

    return ret;
}

int32_t HksServiceOnUkeyInitSession(const struct HksProcessInfo *processInfo, const struct HksBlob *index,
    const struct HksParamSet *inParamSet, struct HksBlob *handle)
{
    int32_t ret = HksCheckBlob2(&processInfo->processName, index);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "Hks check processName or index fail. ret: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(index->size > MAX_SESSION_INDEX_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "index size too large. size: %" LOG_PUBLIC "d. maxSize: %" LOG_PUBLIC "d", index->size, MAX_SESSION_INDEX_SIZE)
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(inParamSet);
    uint32_t handleU32 = 0;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    ret = pluginManager->OnInitSession(processAndError, cppIndex, cppParamSet, handleU32);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OnInitSession fail. ret: %" LOG_PUBLIC "d", ret);
        HksClearThreadExtErrMsg();
        int32_t errVal = 0;
        if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
            errVal = processAndError.errInfo->errVal;
            HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
        }
        HksFreeExternalErrorInfo(processAndError.errInfo);
        struct UKeyReportErrInfo reportErr = { ret, errVal };
        ReportUKeySessionEvent(HKS_EVENT_UKEY_INIT_SESSION, &reportErr, handle, processInfo, inParamSet);
        return ret;
    }

    uint64_t handleU64 = static_cast<uint64_t>(handleU32);
    if (handle->size < sizeof(uint64_t)) {
        HKS_LOG_E("handle size too small. size: %" LOG_PUBLIC "u", handle->size);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = memcpy_s(handle->data, handle->size, &handleU64, sizeof(handleU64));
    if (ret != EOK) {
        HKS_LOG_E("memcpy in HksServiceOnUkeyInitSession fail. ret: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_COPY_FAIL;
    }
    handle->size = sizeof(uint64_t);
    struct UKeyReportErrInfo reportErr = { ret, 0 };
    ReportUKeySessionEvent(HKS_EVENT_UKEY_INIT_SESSION, &reportErr, handle, processInfo, inParamSet);
    return ret;
}

int32_t HksServiceOnUkeyUpdateSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t handleU64 = 0;
    if (handle != nullptr && handle->size == sizeof(uint64_t)) {
        auto mcpRet = memcpy_s(&handleU64, sizeof(handleU64), handle->data, handle->size);
        HKS_IF_TRUE_LOGE_RETURN(mcpRet != EOK, HKS_ERROR_INSUFFICIENT_MEMORY,
        "memcpy_s failed. ret = %" LOG_PUBLIC "d", mcpRet)
    }

    uint32_t handleU32 = static_cast<uint32_t>(handleU64);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> indata;
    if (inData != nullptr && inData->data != nullptr) {
        indata.assign(inData->data, inData->data + inData->size);
    }
    std::vector<uint8_t> outdata;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    int32_t ret = pluginManager->OnUpdateSession(processAndError, handleU32, cppParamSet, indata, outdata);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OnUpdateSession fail. ret: %" LOG_PUBLIC "d", ret);
        HksClearThreadExtErrMsg();
        int32_t errVal = 0;
        if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
            errVal = processAndError.errInfo->errVal;
            HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
        }
        HksFreeExternalErrorInfo(processAndError.errInfo);
        struct UKeyReportErrInfo reportErr = { ret, errVal };
        ReportUKeySessionEvent(HKS_EVENT_UKEY_UPDATE_SESSION, &reportErr, handle, processInfo, paramSet);
        return ret;
    }

    HKS_IF_TRUE_LOGI_RETURN(outData->size == 0, ret, "outData size is 0. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(outData->data == nullptr, ret, "outData data is nullptr. ret: %" LOG_PUBLIC "d", ret);
    if (outData->size < outdata.size()) {
        HKS_LOG_E("updateSession outData size too small. size: %" LOG_PUBLIC "u. needSize: %" LOG_PUBLIC "zu",
        outData->size, outdata.size());
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = memcpy_s(outData->data, outData->size, outdata.data(), outdata.size());
    if (ret != EOK) {
        HKS_LOG_E("memcpy in HksServiceOnUkeyUpdateSession fail. ret: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_COPY_FAIL;
    }
    outData->size = static_cast<uint32_t>(outdata.size());
    struct UKeyReportErrInfo reportErr = { ret, 0 };
    ReportUKeySessionEvent(HKS_EVENT_UKEY_UPDATE_SESSION, &reportErr, handle, processInfo, paramSet);
    return ret;
}

int32_t HksServiceOnUkeyFinishSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData)
{
    uint64_t handleU64 = 0;
    if (handle != nullptr && handle->size == sizeof(uint64_t)) {
        auto mcpRet = memcpy_s(&handleU64, sizeof(handleU64), handle->data, handle->size);
        HKS_IF_TRUE_LOGE_RETURN(mcpRet != EOK, HKS_ERROR_INSUFFICIENT_MEMORY,
        "memcpy_s failed. ret = %" LOG_PUBLIC "d", mcpRet)
    }
    uint32_t handleU32 = static_cast<uint32_t>(handleU64);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> indata;
    if (inData != nullptr && inData->data != nullptr) {
        indata.assign(inData->data, inData->data + inData->size);
    }
    std::vector<uint8_t> outdata;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    int32_t ret = pluginManager->OnFinishSession(processAndError, handleU32, cppParamSet, indata, outdata);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OnFinishSession fail. ret: %" LOG_PUBLIC "d", ret);
        HksClearThreadExtErrMsg();
        int32_t errVal = 0;
        if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
            errVal = processAndError.errInfo->errVal;
            HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
        }
        HksFreeExternalErrorInfo(processAndError.errInfo);
        struct UKeyReportErrInfo reportErr = { ret, errVal };
        ReportUKeySessionEvent(HKS_EVENT_UKEY_FINISH_SESSION, &reportErr, handle, processInfo, paramSet);
        return ret;
    }

    HKS_IF_TRUE_LOGI_RETURN(outData->size == 0, ret, "outData size is 0. ret: %" LOG_PUBLIC "d", ret);
    HKS_IF_TRUE_LOGI_RETURN(outData->data == nullptr, ret, "outData data is nullptr. ret: %" LOG_PUBLIC "d", ret);
    if (outData->size < outdata.size()) {
        HKS_LOG_E("finishSession outData size too small. size: %" LOG_PUBLIC "u. needSize: %" LOG_PUBLIC "zu",
        outData->size, outdata.size());
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = memcpy_s(outData->data, outData->size, outdata.data(), outdata.size());
    if (ret != EOK) {
        HKS_LOG_E("memcpy in HksServiceOnUkeyFinishSession fail. ret: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_COPY_FAIL;
    }
    outData->size = static_cast<uint32_t>(outdata.size());
    struct UKeyReportErrInfo reportErr = { ret, 0 };
    ReportUKeySessionEvent(HKS_EVENT_UKEY_FINISH_SESSION, &reportErr, handle, processInfo, paramSet);
    return ret;
}

int32_t HksServiceOnUkeyAbortSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet)
{
    uint64_t handleU64 = 0;
    if (handle != nullptr && handle->size == sizeof(uint64_t)) {
        auto mcpRet = memcpy_s(&handleU64, sizeof(handleU64), handle->data, handle->size);
        HKS_IF_TRUE_LOGE_RETURN(mcpRet != EOK, HKS_ERROR_INSUFFICIENT_MEMORY,
            "memcpy_s failed. ret = %" LOG_PUBLIC "d", mcpRet)
    }
    auto handleU32 = static_cast<uint32_t>(handleU64);
    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")
    CppParamSet cppParamSet(paramSet);
    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    int32_t ret = pluginManager->OnAbortSession(processAndError, handleU32, cppParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OnAbortSession fail. ret: %" LOG_PUBLIC "d", ret);
        HksClearThreadExtErrMsg();
        int32_t errVal = 0;
        if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
            errVal = processAndError.errInfo->errVal;
            HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
        }
        HksFreeExternalErrorInfo(processAndError.errInfo);
        struct UKeyReportErrInfo reportErr = { ret, errVal };
        ReportUKeySessionEvent(HKS_EVENT_UKEY_ABORT_SESSION, &reportErr, handle, processInfo, paramSet);
        return ret;
    }
    struct UKeyReportErrInfo reportErr = { ret, 0 };
    ReportUKeySessionEvent(HKS_EVENT_UKEY_ABORT_SESSION, &reportErr, handle, processInfo, paramSet);
    return ret;
}

int32_t HksServiceOnUkeyImportWrappedKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    int32_t ret = HksCheckBlob3(&processInfo->processName, keyAlias, wrappingKeyAlias);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Hks check processName or keyAlias or wrappingKeyAlias fail. ret: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(keyAlias->size > MAX_SESSION_INDEX_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "keyAlias size too large. size: %" LOG_PUBLIC "d. maxSize: %" LOG_PUBLIC "d",
        keyAlias->size, MAX_SESSION_INDEX_SIZE)
    HKS_IF_TRUE_LOGE_RETURN(wrappingKeyAlias->size > MAX_SESSION_INDEX_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "wrappingKeyAlias size too large. size: %" LOG_PUBLIC "d. maxSize: %" LOG_PUBLIC "d",
        wrappingKeyAlias->size, MAX_SESSION_INDEX_SIZE)
    std::string cppIndex(reinterpret_cast<const char*>(keyAlias->data), keyAlias->size);
    std::string cppWrappingKeyIndex(reinterpret_cast<const char*>(wrappingKeyAlias->data), wrappingKeyAlias->size);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> wrappedData;
    if (wrappedKeyData != nullptr && wrappedKeyData->data != nullptr && wrappedKeyData->size != 0) {
        wrappedData.assign(wrappedKeyData->data, wrappedKeyData->data + wrappedKeyData->size);
    }

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    ret = pluginManager->OnImportWrappedKey(processAndError, cppIndex, cppWrappingKeyIndex,
        cppParamSet, wrappedData);
    HKS_IF_TRUE_RETURN(ret == HKS_SUCCESS, HKS_SUCCESS)

    HKS_LOG_E("OnImportWrappedKey fail. ret: %" LOG_PUBLIC "d", ret);
    HksClearThreadExtErrMsg();
    int32_t errVal = 0;
    if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
        errVal = processAndError.errInfo->errVal;
        HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
    }
    HksFreeExternalErrorInfo(processAndError.errInfo);
    struct UKeyReportErrInfo reportErr = { ret, errVal };
    ReportUKeyKeyEvent(HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY, &reportErr, processInfo, paramSet);
    return ret;
}

int32_t HksServiceOnUkeyExportPublicKey(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    int32_t ret = HksCheckBlob3(&processInfo->processName, keyAlias, key);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Hks check processName or keyAlias or key fail. ret: %" LOG_PUBLIC "d", ret)

    HKS_IF_TRUE_LOGE_RETURN(keyAlias->size > MAX_SESSION_INDEX_SIZE, HKS_ERROR_INVALID_ARGUMENT,
        "keyAlias size too large. size: %" LOG_PUBLIC "d. maxSize: %" LOG_PUBLIC "d",
        keyAlias->size, MAX_SESSION_INDEX_SIZE)

    std::string cppIndex(reinterpret_cast<const char*>(keyAlias->data), keyAlias->size);
    CppParamSet cppParamSet(paramSet);
    std::vector<uint8_t> outdata;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get PluginManager instance.")

    struct HksProcessWithErrorInfo processAndError = { processInfo, nullptr };
    ret = pluginManager->OnExportPublicKey(processAndError, cppIndex, cppParamSet, outdata);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("OnExportPublicKey fail. ret: %" LOG_PUBLIC "d", ret);
        HksClearThreadExtErrMsg();
        int32_t errVal = 0;
        if (processAndError.errInfo != nullptr && processAndError.errInfo->hasErrorInfo) {
            errVal = processAndError.errInfo->errVal;
            HksAppendThreadExtErrMsg(processAndError.errInfo->errVal, processAndError.errInfo->errorDesc);
        }
        HksFreeExternalErrorInfo(processAndError.errInfo);
        struct UKeyReportErrInfo reportErr = { ret, errVal };
        ReportUKeyKeyEvent(HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY, &reportErr, processInfo, paramSet);
        return ret;
    }

    if (key->size < outdata.size()) {
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
