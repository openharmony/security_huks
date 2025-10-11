#include "hks_ipc_service_provider_adapter.h"
#include "hks_ipc_service_provider.h"
#include "hks_ukey_common.h"
#include "securec.h"
#include <string>
#include <vector>

// 适配器模式
int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet)
{
    HKS_LOG_E("==========ksIpcServiceProviderRegisterAdapter income");

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
    ret = OHOS::Security::Huks::HksIpcServiceOnCreateRemoteKeyHandle(processInfo, cppresourceId, cppParamSet, remoteHandle);

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
    ret = OHOS::Security::Huks::HksIpcServiceOnFindRemoteKeyHandle(processInfo, cppresourceId, cppParamSet, remoteHandle);

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

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet)
{
    int32_t ret = 0;
    std::string cppProviderName(reinterpret_cast<const char*>(providerName->data), providerName->size);
    std::string certificates;
    CppParamSet cppParamSet(paramSet);

    ret = OHOS::Security::Huks::HksIpcServiceOnExportProviderAllCertificates(processInfo, cppProviderName, cppParamSet, certificates);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "HksIpcExportProvCertsAdapter fail")

    ret = OHOS::Security::Huks::JsonArrayToCertInfoSet(certificates, *certInfoSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "JsonArrayToCertInfoSet fail")

    return ret;
}

int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *resourceId, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet)
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
    return OHOS::Security::Huks::HksIpcServiceOnAuthUkeyPin(processInfo, cppresourceId, cppParamSet, *outStatus, *retryCount);
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
    std::string cppresourceId(reinterpret_cast<const char*>(resourceId->data), resourceId->size);
    return OHOS::Security::Huks::HksIpcServiceOnClearPinStatus(processInfo, cppresourceId);
}