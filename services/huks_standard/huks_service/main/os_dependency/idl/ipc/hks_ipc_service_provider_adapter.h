// hks_ipc_service_providerAdapter_adapter.h
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksIpcServiceProviderRegisterAdapter(const struct HksBlob *srcData, const uint8_t *context);
void HksIpcServiceProviderUnRegisterAdapter(const struct HksBlob *srcData, const uint8_t *context);
void HksIpcServiceRegistLibFunctionAdapter(int32_t funCode, void *fun);

int HksIpcServiceOnCreateRemoteIndexAdapter(const char *providerName, const uint8_t *paramSet, uint32_t paramSetLen, char *outIndex, uint32_t outIndexLen);
int HksIpcServiceOnCreateRemoteKeyHandleAdapter(const char *index);
int HksIpcServiceOnFindRemoteKeyHandleAdapter(const char *index, char *keyIndex, uint32_t keyIndexLen);
int HksIpcServiceOnCloseRemoteKeyHandleAdapter(const char *index, char *keyIndex, uint32_t keyIndexLen);

int HksIpcServiceOnSignedAdapter(const char *index, const uint8_t *paramSet, uint32_t paramSetLen, uint8_t *outData, uint32_t *outDataLen);
int HksIpcServiceOnAuthUkeyPinAdapter(const char *index, const uint8_t *pinData, uint32_t pinDataLen, bool *outStatus, int32_t *retryCnt);
int HksIpcServiceOnGetVerifyPinStatusAdapter(const char *index, int32_t *pinStatus);
int HksIpcServiceOnClearPinStatusAdapter(const char *index);

int HksIpcServiceOnListProvidersAdapter(uint8_t *providersOut, uint32_t *providersOutLen);
int HksIpcServiceOnFindProviderCertificateAdapter(const char *index, uint8_t *certificatesOut, uint32_t *certificatesOutLen);
int HksIpcServiceOnListProviderAllCertificateAdapter(const char *providerName, char *certificatesOut, uint32_t certificatesOutLen);

#ifdef __cplusplus
}
#endif