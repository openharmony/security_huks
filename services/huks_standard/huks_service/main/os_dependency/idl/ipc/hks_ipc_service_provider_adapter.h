// hks_ipc_service_providerAdapter_adapter.h
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// 注册注销
int HksIpcServiceOnProviderRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);
int HksIpcServiceOnProviderUnRegisterAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);

int HksIpcServiceOnCreateRemoteIndexAdapter(const char *providerName, const uint8_t *paramSet, uint32_t paramSetLen, 
    char *outIndex, uint32_t outIndexLen);

int HksIpcServiceOnCreateRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int HksIpcServiceOnFindRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int HksIpcServiceOnCloseRemoteKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *index, 
    const struct HksParamSet *paramSet);

int HksIpcServiceOnSignedAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int HksIpcServiceOnVerifyAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int HksIpcServiceOnAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus, int32_t *retryCnt);

int HksIpcServiceOnGetVerifyPinStatusAdapter(const char *index, int32_t *pinStatus);
int HksIpcServiceOnClearPinStatusAdapter(const char *index);

int HksIpcServiceOnListProvidersAdapter(uint8_t *providersOut, uint32_t *providersOutLen);
int HksIpcServiceOnFindProviderCertificateAdapter(const char *index, uint8_t *certificatesOut, uint32_t *certificatesOutLen);
int HksIpcServiceOnListProviderAllCertificateAdapter(const char *providerName, char *certificatesOut, uint32_t certificatesOutLen);

#ifdef __cplusplus
}
#endif