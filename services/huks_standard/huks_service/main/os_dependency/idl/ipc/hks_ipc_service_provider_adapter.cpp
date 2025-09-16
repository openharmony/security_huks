#include "hks_ipc_service_provider_adapter.h"
#include "hks_ipc_service_provider.h"
#include <string>
#include <vector>

// 适配器模式
void HksIpcServiceProviderRegisterAdapter(const struct HksBlob *srcData, const uint8_t *context)
{
    HksIpcServiceProviderRegister(srcData, context);
    return;
}

void HksIpcServiceProviderUnRegisterAdapter(const struct HksBlob *srcData, const uint8_t *context)
{
    return;
}

void HksIpcServiceRegistLibFunctionAdapter(int32_t funCode, void *fun)
{
    return;
}

int HksIpcServiceOnCreateRemoteIndexAdapter(const char *providerName, const uint8_t *paramSet, uint32_t paramSetLen, char *outIndex, uint32_t outIndexLen)
{
    return 0;
}

int HksIpcServiceOnCreateRemoteKeyHandleAdapter(const char *index)
{
    return 0;
}

int HksIpcServiceOnFindRemoteKeyHandleAdapter(const char *index, char *keyIndex, uint32_t keyIndexLen)
{
    return 0;
}

int HksIpcServiceOnCloseRemoteKeyHandleAdapter(const char *index, char *keyIndex, uint32_t keyIndexLen)
{
    return 0;
}

int HksIpcServiceOnSignedAdapter(const char *index, const uint8_t *paramSet, uint32_t paramSetLen, uint8_t *outData, uint32_t *outDataLen)
{
    return 0;
}

int HksIpcServiceOnAuthUkeyPinAdapter(const char *index, const uint8_t *pinData, uint32_t pinDataLen, bool *outStatus, int32_t *retryCnt)
{
    return 0;
}

int HksIpcServiceOnGetVerifyPinStatusAdapter(const char *index, int32_t *pinStatus)
{
    return 0;
}

int HksIpcServiceOnClearPinStatusAdapter(const char *index)
{
    return 0;
}

int HksIpcServiceOnListProvidersAdapter(uint8_t *providersOut, uint32_t *providersOutLen)
{
    return 0;
}

int HksIpcServiceOnFindProviderCertificateAdapter(const char *index, uint8_t *certificatesOut, uint32_t *certificatesOutLen)
{
    return 0;
}

int HksIpcServiceOnListProviderAllCertificateAdapter(const char *providerName, char *certificatesOut, uint32_t certificatesOutLen)
{
    return 0;
}