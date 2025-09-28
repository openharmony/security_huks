// hks_ipc_service_providerAdapter_adapter.h
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// 注册注销
int32_t HksIpcServiceOnProviderRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);
int32_t HksIpcServiceOnProviderUnRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);

int32_t HksIpcServiceOnCreateRemoteIndexAdapter(const char *providerName, const uint8_t *paramSet, uint32_t paramSetLen, 
    char *outIndex, uint32_t outIndexLen);

int32_t HksIpcServiceOnCreateRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int32_t HksIpcServiceOnFindRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int32_t HksIpcServiceOnCloseRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet);

int32_t HksIpcServiceOnSignedAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int32_t HksIpcServiceOnVerifyAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int32_t HksIpcServiceOnExportProviderCertificatesAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcServiceExportCertificateAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcServiceOnAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus, uint32_t *retryCount);

int32_t HksIpcServiceOnGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus);

int32_t HksIpcServiceOnGetVerifyPinStatusAdapter(const char *index, int32_t *pinStatus);
int32_t HksIpcServiceOnClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index);

int32_t HksIpcServiceOnListProvidersAdapter(uint8_t *providersOut, uint32_t *providersOutLen);
int32_t HksIpcServiceOnFindProviderCertificateAdapter(const char *index, uint8_t *certificatesOut, uint32_t *certificatesOutLen);
int32_t HksIpcServiceOnListProviderAllCertificateAdapter(const char *providerName, char *certificatesOut, uint32_t certificatesOutLen);

#ifdef __cplusplus
}
#endif