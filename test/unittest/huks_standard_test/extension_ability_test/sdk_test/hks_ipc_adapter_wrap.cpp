#include "hks_type.h"
#include "hks_ipc_service_provider_adapter.h"
#include <cstring>

extern "C" {

int32_t __wrap_HksIpcProviderRegAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcProviderUnregAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcCreateRemKeyHandleAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, HksBlob *remoteHandleOut)
{
    if (remoteHandleOut) remoteHandleOut->size = 0;
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcGetRemoteHandleAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, HksBlob *remoteHandleOut)
{
    if (remoteHandleOut) remoteHandleOut->size = 0;
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcCloseRemKeyHandleAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcSignAdapter(const HksProcessInfo*, const HksParamSet*, const HksBlob*, const HksBlob*, HksBlob *signatureOut)
{
    if (signatureOut && signatureOut->data && signatureOut->size > 0) memset(signatureOut->data, 0xAA, signatureOut->size);
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcVerifyAdapter(const HksProcessInfo*, const HksParamSet*, const HksBlob*, const HksBlob*, HksBlob *signatureOut)
{
    if (signatureOut) signatureOut->size = 0;
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcExportProvCertsAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, HksExtCertInfoSet*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcExportCertAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, HksExtCertInfoSet*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcAuthUkeyPinAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, int32_t *outStatus, uint32_t *retryCount)
{
    if (outStatus) *outStatus = 0;
    if (retryCount) *retryCount = 0;
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcGetUkeyPinAuthStateAdapter(const HksProcessInfo*, const HksBlob*, const HksParamSet*, int32_t *outStatus)
{
    if (outStatus) *outStatus = 0;
    return HKS_SUCCESS;
}
int32_t __wrap_HksIpcClearPinStatusAdapter(const HksProcessInfo*, const HksBlob*) { return HKS_SUCCESS; }
int32_t __wrap_HksIpcServiceOnGetRemotePropertyAdapter(const HksProcessInfo*, const HksBlob*, const HksBlob*, const HksParamSet*, const uint8_t*)
{
    return HKS_SUCCESS;
}

} // extern "C"