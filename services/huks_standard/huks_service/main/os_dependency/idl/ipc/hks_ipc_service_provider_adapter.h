// hks_ipc_service_providerAdapter_adapter.h
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// 注册注销
int32_t HksIpcProviderRegAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);
int32_t HksIpcProviderUnregAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *name, 
    const struct HksParamSet *paramSet);

int32_t HksIpcCreateRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int32_t HksIpcGetRemoteHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId, 
    const struct HksParamSet *paramSet, struct HksBlob *remoteHandleOut);

int32_t HksIpcCloseRemKeyHandleAdapter(const struct HksProcessInfo *processInfo,  const struct HksBlob *resourceId, 
    const struct HksParamSet *paramSet);

int32_t HksIpcSignAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int32_t HksIpcVerifyAdapter(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *index, const struct HksBlob *data, struct HksBlob *signatureOut);

int32_t HksIpcExportProvCertsAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *providerName, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcExportCertAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index, const struct HksParamSet *paramSet, struct HksExtCertInfoSet *certInfoSet);

int32_t HksIpcAuthUkeyPinAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus, uint32_t *retryCount);

int32_t HksIpcGetUkeyPinAuthStateAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *index, const struct HksParamSet *paramSet, int32_t *outStatus);

int32_t HksIpcClearPinStatusAdapter(const struct HksProcessInfo *processInfo, const struct HksBlob *index);

int32_t HksIpcServiceOnGetRemotePropertyAdapter(const struct HksProcessInfo *processInfo,
    const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSet, const uint8_t *remoteObject);

#ifdef __cplusplus
}
#endif