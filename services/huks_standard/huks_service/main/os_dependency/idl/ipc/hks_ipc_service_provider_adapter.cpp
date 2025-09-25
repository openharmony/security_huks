#include "hks_ipc_service_provider_adapter.h"
#include "hks_ipc_service_provider.h"
#include "securec.h"
#include <string>
#include <vector>

// 适配器模式
int32_t HksIpcServiceOnProviderRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet)
{
    HKS_LOG_E("==========ksIpcServiceProviderRegisterAdapter income");

    std::string cppIndex(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderRegister(processInfo, cppIndex, cppParamSet);
}

int32_t HksIpcServiceOnProviderUnRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet)
{

    std::string cppIndex(reinterpret_cast<const char*>(name->data), name->size);
    CppParamSet cppParamSet(paramSet);

    return OHOS::Security::Huks::HksIpcServiceProviderRegister(processInfo, cppIndex, cppParamSet);
}

int32_t HksIpcServiceOnCreateRemoteIndexAdapter(const char *providerName, const uint8_t *paramSet, uint32_t paramSetLen, 
    char *outIndex, uint32_t outIndexLen)
{
    return 0;
}

int32_t HksIpcServiceOnCreateRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(paramSet);

    std::string remoteHandle;
    OHOS::Security::Huks::HksIpcServiceOnCreateRemoteKeyHandle(processInfo, cppIndex, cppParamSet, remoteHandle);

    uint32_t copyLen = std::min(remoteHandleOut->size, static_cast<uint32_t>(remoteHandle.size()));
    memcpy_s(remoteHandleOut->data, remoteHandleOut->size, remoteHandle.data(), copyLen);
    remoteHandleOut->size = copyLen;

    // TODO: 错误特判处理
    return 0;
}

int32_t HksIpcServiceOnFindRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  
    const struct HksBlob *index, const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(paramSet);

    std::string remoteHandle;
    // OHOS::Security::Huks::HksIpcServiceOnFindRemoteKeyHandle(processInfo, cppIndex, cppParamSet, remoteHandle);

    uint32_t copyLen = std::min(remoteHandleOut->size, static_cast<uint32_t>(remoteHandle.size()));
    memcpy_s(remoteHandleOut->data, remoteHandleOut->size, remoteHandle.data(), copyLen);
    remoteHandleOut->size = copyLen;

    // TODO: 错误特判处理
    return 0;
}

int32_t HksIpcServiceOnCloseRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(paramSet);

    // return OHOS::Security::Huks::HksIpcServiceOnCloseRemoteKeyHandle(processInfo, cppIndex, cppParamSet);
    return 0;
}

int32_t HksIpcServiceOnSignedAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    std::string cppSrcData(reinterpret_cast<const char*>(srcData->data), srcData->size);
    CppParamSet cppParamSet(paramSet);

    std::string signature;
    // OHOS::Security::Huks::HksIpcServiceOnSigned(processInfo, cppIndex, cppParamSet, cppSrcData, signature);

    uint32_t copyLen = std::min(signatureOut->size, static_cast<uint32_t>(signature.size()));
    memcpy_s(signatureOut->data, signatureOut->size, signature.data(), copyLen);
    signatureOut->size = copyLen;

    // TODO: 错误特判处理
    return 0;
}

int32_t HksIpcServiceOnVerifyAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    std::string cppData(reinterpret_cast<const char*>(data->data), data->size);
    CppParamSet cppParamSet(paramSet);

    std::string signature;
    // OHOS::Security::Huks::HksIpcServiceOnVerify(processInfo, cppIndex, cppParamSet, cppData, signature);

    uint32_t copyLen = std::min(signatureOut->size, static_cast<uint32_t>(signature.size()));
    memcpy_s(signatureOut->data, signatureOut->size, signature.data(), copyLen);
    signatureOut->size = copyLen;

    // TODO: 错误特判处理
    return 0;
}

int32_t HksIpcServiceOnAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus, int32_t *retryCnt)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    CppParamSet cppParamSet(paramSet);
    // return OHOS::Security::Huks::HksIpcServiceOnAuthUkeyPin(cppIndex, cppParamSet, retryCount);
    return 0;
}

int32_t HksIpcServiceOnGetVerifyPinStatusAdapter(const char *index, int32_t *pinStatus)
{
    return 0;
}

int32_t HksIpcServiceOnClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index)
{
    std::string cppIndex(reinterpret_cast<const char*>(index->data), index->size);
    // return OHOS::Security::Huks::HksIpcServiceOnClearPinStatus(processInfo, cppIndex);
    return 0;
}

int32_t HksIpcServiceOnListProvidersAdapter(uint8_t *providersOut, uint32_t *providersOutLen)
{
    return 0;
}

int32_t HksIpcServiceOnFindProviderCertificateAdapter(const char *index, uint8_t *certificatesOut, uint32_t *certificatesOutLen)
{
    return 0;
}

int32_t HksIpcServiceOnListProviderAllCertificateAdapter(const char *providerName, char *certificatesOut, uint32_t certificatesOutLen)
{
    return 0;
}