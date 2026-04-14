/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifndef HKS_UNTRUSTED_RUNNING_ENV

#include "hks_dcm_callback_handler.h"

#include <cinttypes>
#include <cstdint>
#include <dlfcn.h>
#include <map>
#include <mutex>
#include <new>
#include <refbase.h>
#include <securec.h>
#include <string>
#include <unordered_map>

#include "hks_log.h"
#include "hks_report.h"
#include "hks_sa_interface.h"
#include "hks_template.h"
#include "hks_type.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace Security {
namespace Hks {

class ThreadSafeMap {
public:
    std::mutex &GetMutex()
    {
        return mContainerLock;
    }
    int32_t SetNewInstanceWithoutLock(sptr<IHksService> index, uint64_t value)
    {
        typename std::map<sptr<IHksService>, uint64_t>::iterator position = mValues.find(index);
        HKS_IF_TRUE_LOGE_RETURN(position != mValues.end(), HKS_ERROR_ALREADY_EXISTS,
            "SetNewInstance: current value exist requestId = %" LOG_PUBLIC PRIu64, position->second)
        mValues[index] = value;
        return HKS_SUCCESS;
    }
    sptr<IHksService> GetProxyWithoutLock(uint64_t value)
    {
        auto position = findInMapByValue(value);
        HKS_IF_TRUE_LOGE_RETURN(position == mValues.end(), nullptr,
            "GetProxyWithoutLock: current value not exist, requestId %" LOG_PUBLIC PRIu64, value)
        return position->first;
    }
    void RemoveWithoutLock(uint64_t value)
    {
        auto position = findInMapByValue(value);
        HKS_IF_TRUE_LOGE_RETURN_VOID(position == mValues.end(),
            "RemoveWithoutLock: current value not exist, requestId %" LOG_PUBLIC PRIu64, value)
        mValues.erase(position);
    }
private:
    std::mutex mContainerLock{};
    std::map<sptr<IHksService>, uint64_t> mValues{};
    std::map<sptr<IHksService>, uint64_t>::iterator findInMapByValue(uint64_t value)
    {
        return std::find_if(
            mValues.begin(), mValues.end(), [value](const std::pair<sptr<IHksService>, uint64_t> &element) {
            return element.second == value;
        });
    }
};

int32_t CopyBlobToBuffer(const struct DcmBlob *blob, struct HksBlob *buf)
{
    HKS_IF_TRUE_LOGE_RETURN(buf->size < sizeof(blob->size) + ALIGN_SIZE(blob->size), HKS_ERROR_BUFFER_TOO_SMALL,
        "buf size smaller than blob size")
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(buf->data, buf->size, &blob->size, sizeof(blob->size)),
        HKS_ERROR_BUFFER_TOO_SMALL, "copy buf fail")
    buf->data += sizeof(blob->size);
    buf->size -= sizeof(blob->size);
    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(buf->data, buf->size, blob->data, blob->size),
        HKS_ERROR_BUFFER_TOO_SMALL, "copy buf fail")
    buf->data += ALIGN_SIZE(blob->size);
    buf->size -= ALIGN_SIZE(blob->size);
    return HKS_SUCCESS;
}

int32_t PackAttestChain(struct DcmCertChain *certChain, struct HksBlob *certChainPacked)
{
    HKS_IF_TRUE_LOGE_RETURN(certChain == nullptr || certChain->certs == nullptr, HKS_ERROR_NULL_POINTER,
        "certChain buffer from caller is null.")
    HKS_IF_TRUE_LOGE_RETURN(certChain->certsCount == 0 || certChain->certsCount > HKS_CERT_COUNT,
        HKS_ERROR_BUFFER_TOO_SMALL, "certs count %" LOG_PUBLIC "u is not correct", certChain->certsCount)
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        HKS_IF_TRUE_LOGE_RETURN(certChain->certs[i].data == nullptr || certChain->certs[i].size == 0 ||
            certChain->certs[i].size > HKS_CERT_APP_SIZE, HKS_ERROR_INVALID_ARGUMENT,
            "cert %" LOG_PUBLIC "u is null or cert size %" LOG_PUBLIC "u invalid ", i, certChain->certs[i].size)
    }

    struct HksBlob tmp = *certChainPacked;
    HKS_IF_TRUE_LOGE_RETURN(tmp.size <= sizeof(uint32_t), HKS_ERROR_BUFFER_TOO_SMALL,
        "certChainPacked size too small")
    *((uint32_t *)tmp.data) = certChain->certsCount;
    tmp.data += sizeof(uint32_t);
    tmp.size -= sizeof(uint32_t);
    int32_t ret = 0;

    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        if (certChain->certs[i].data == nullptr) {
            HKS_LOG_E("single cert %" LOG_PUBLIC "u from huks is null.", i);
            ret = HKS_ERROR_NULL_POINTER;
            break;
        }
        ret = CopyBlobToBuffer(&certChain->certs[i], &tmp);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "copy cert fail")
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "PackAttestChain fail")
    certChainPacked->size = tmp.data - certChainPacked->data;
    return HKS_SUCCESS;
}

std::mutex g_dcmSoMutex{};
ThreadSafeMap g_instancesList{};
ThreadSafeMap g_offlineInstanceList{};
void *g_certMgrSdkHandle{};
std::unordered_map<std::string, void*> g_dcmFunctions{};

}}} // OHOS::Security::Hks

using OHOS::Security::Hks::g_dcmSoMutex;
using OHOS::Security::Hks::g_instancesList;
using OHOS::Security::Hks::g_offlineInstanceList;
using OHOS::Security::Hks::g_certMgrSdkHandle;
using OHOS::Security::Hks::g_dcmFunctions;
using OHOS::Security::Hks::IHksService;
using OHOS::Security::Hks::PackAttestChain;
using OHOS::sptr;

static void SafeLogString(DcmBlob erroInfo)
{
    constexpr uint32_t maxLogStrLen = 250;
    if (erroInfo.data == nullptr || erroInfo.size == 0 || erroInfo.size >= maxLogStrLen) {
        HKS_LOG_E("OfflineAnonAttest fail Invalid erroInfo size: %" LOG_PUBLIC "u", erroInfo.size);
        return;
    }
    char *data = reinterpret_cast<char*>(erroInfo.data);
    uint32_t size = erroInfo.size;

    if (data[size - 1] == '\0') {
        HKS_LOG_E("OfflineAnonAttest fail, DCM ERROR INFO: %" LOG_PUBLIC "s", data);
        return;
    }
    
    char logStr[maxLogStrLen] = {};
    int32_t ret = memcpy_s(logStr, sizeof(logStr), data, size);
    if (ret != EOK) {
        HKS_LOG_E("memcpy_s failed, ret=%" LOG_PUBLIC "d", ret);
        return;
    }
    
    logStr[size] = '\0';
    HKS_LOG_E("OfflineAnonAttest fail, DCM ERROR INFO: %" LOG_PUBLIC "s", logStr);
}

static int32_t MapDcmErrorCodeToHuks(DcmAnonymousResponse *response)
{
    switch (response->errCode) {
        case DCM_ERROR_NETWORK_UNAVALIABLE:
            return HKS_ERROR_CODE_NETWORK_UNAVAILABLE;
        
        case DCM_ERROR_SERVICE_TIME_OUT:
            return HUKS_ERR_CODE_BUSY;
        
        case DCM_ERROR_INVALID_PRIVACY_KEY:
            SafeLogString(response->errInfo);
            return HKS_ERROR_CODE_DCM_CALLBACK_ERROR;
        
        default:
            return HKS_ERROR_CODE_DCM_CALLBACK_ERROR;
    }
}

void HksDcmOfflineCallback(DcmAnonymousResponse *response)
{
    if (response == nullptr) {
        HKS_LOG_E("dcm callback got null response");
        HksReport(__func__, nullptr, nullptr, HUKS_ERR_CODE_EXTERNAL_ERROR);
        return;
    }
    
    int32_t hksErrorCode = HKS_SUCCESS;
    if (response->errCode != DCM_SUCCESS) {
        HksReport(__func__, nullptr, nullptr, response->errCode);
        hksErrorCode = MapDcmErrorCodeToHuks(response);
    }
    HKS_LOG_I("dcm callback requestId %" LOG_PUBLIC PRIu64, response->requestId);
    std::lock_guard<std::mutex> lockGuard(g_offlineInstanceList.GetMutex());
    sptr<IHksService> hksProxy = g_offlineInstanceList.GetProxyWithoutLock(response->requestId);
    HKS_IF_NULL_LOGE_RETURN_VOID(hksProxy, "GetProxyWithoutLock failed requestId %" LOG_PUBLIC PRIu64,
        response->requestId)
    std::unique_ptr<uint8_t[]> replyData = nullptr;
    uint32_t replySize = 0;
    do {
        HKS_IF_NOT_SUCC_LOGE_BREAK(hksErrorCode, "HksDcmOfflineCallback failed %" LOG_PUBLIC "d", response->errCode)
        uint32_t packedSize = HKS_CERT_ROOT_SIZE + HKS_CERT_CA_SIZE + HKS_CERT_DEVICE_SIZE + HKS_CERT_APP_SIZE;
        auto packedCertChain = std::make_unique<uint8_t[]>(packedSize);
        HKS_IF_NULL_LOGE_BREAK(packedCertChain, "new cert chain buffer failed")
        HksBlob packedBlob { .size = packedSize, .data = packedCertChain.get() };
        int ret = PackAttestChain(response->certChain, &packedBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PackAttestChain failed %" LOG_PUBLIC "d", ret)
        replyData = std::move(packedCertChain);
        replySize = packedBlob.size;
    } while (0);

    hksProxy->SendAsyncReply(hksErrorCode, replyData, replySize);
    g_offlineInstanceList.RemoveWithoutLock(response->requestId);
}

void HksDcmCallback(DcmAnonymousResponse *response)
{
    if (response == nullptr) {
        HKS_LOG_E("dcm callback got null response");
        HksReport(__func__, nullptr, nullptr, HUKS_ERR_CODE_EXTERNAL_ERROR);
        return;
    }

    int32_t hksErrorCode = HKS_SUCCESS;
    if (response->errCode != DCM_SUCCESS) {
        HksReport(__func__, nullptr, nullptr, response->errCode);
        hksErrorCode = HUKS_ERR_CODE_EXTERNAL_ERROR;
    }
    HKS_LOG_I("dcm callback requestId %" LOG_PUBLIC PRIu64, response->requestId);
    std::lock_guard<std::mutex> lockGuard(g_instancesList.GetMutex());
    sptr<IHksService> hksProxy = g_instancesList.GetProxyWithoutLock(response->requestId);
    HKS_IF_NULL_LOGE_RETURN_VOID(hksProxy, "GetProxyWithoutLock failed *requestId %" LOG_PUBLIC PRIu64,
        response->requestId)
    std::unique_ptr<uint8_t[]> replyData = nullptr;
    uint32_t replySize = 0;
    do {
        HKS_IF_NOT_SUCC_LOGE_BREAK(response->errCode, "HksDcmCallback failed %" LOG_PUBLIC "d", response->errCode)
        uint32_t packedSize = HKS_CERT_ROOT_SIZE + HKS_CERT_CA_SIZE + HKS_CERT_DEVICE_SIZE + HKS_CERT_APP_SIZE;
        auto packedCertChain = std::make_unique<uint8_t[]>(packedSize);
        HKS_IF_NULL_LOGE_BREAK(packedCertChain, "new cert chain buffer failed")
        HksBlob packedBlob { .size = packedSize, .data = packedCertChain.get() };
        int ret = PackAttestChain(response->certChain, &packedBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PackAttestChain failed %" LOG_PUBLIC "d", ret)
        replyData = std::move(packedCertChain);
        replySize = packedBlob.size;
    } while (false);

    hksProxy->SendAsyncReply(hksErrorCode, replyData, replySize);
    g_instancesList.RemoveWithoutLock(response->requestId);
}

int32_t HksDcmCallbackHandlerSetRequestIdWithoutLock(const uint8_t *remoteObject, uint64_t requestId)
{
    auto hksProxy = OHOS::iface_cast<IHksService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));
    HKS_IF_NULL_LOGE_RETURN(hksProxy, HKS_ERROR_NULL_POINTER, "iface_cast IHksService failed")
    int ret = g_instancesList.SetNewInstanceWithoutLock(hksProxy, requestId);
    HKS_IF_NOT_SUCC_LOGE(ret, "g_instancesList.SetNewInstance failed %" LOG_PUBLIC "d", ret)
    return ret;
}

int32_t HksDcmOfflineCallbackHandlerSetRequestIdWithoutLock(const uint8_t *remoteObject, uint64_t requestId)
{
    auto hksProxy = OHOS::iface_cast<IHksService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));
    HKS_IF_NULL_LOGE_RETURN(hksProxy, HKS_ERROR_NULL_POINTER, "iface_cast IHksService failed")
    int ret = g_offlineInstanceList.SetNewInstanceWithoutLock(hksProxy, requestId);
    HKS_IF_NOT_SUCC_LOGE(ret, "g_offlineInstanceList.SetNewInstance failed %" LOG_PUBLIC "d", ret)
    return ret;
}

std::mutex &HksDcmCallbackHandlerGetMapMutex(void)
{
    return g_instancesList.GetMutex();
}

std::mutex &HksDcmOfflineCallbackHandlerGetMapMutex(void)
{
    return g_offlineInstanceList.GetMutex();
}

void HksCloseDcmFunction(void)
{
    std::lock_guard<std::mutex> lck(g_dcmSoMutex);
    if (g_certMgrSdkHandle == nullptr) {
        return;
    }
    int ret = dlclose(g_certMgrSdkHandle);
    HKS_IF_TRUE_LOGE(ret != 0, "dlclose g_certMgrSdkHandle failed %" LOG_PUBLIC "d %" LOG_PUBLIC "s", ret, dlerror())
    g_certMgrSdkHandle = nullptr;
    g_dcmFunctions.clear();
}

template<typename T>
T HksGetDcmFunction(const char* functionName)
{
    if (functionName == nullptr) {
        HKS_LOG_E("functionName is null");
        return nullptr;
    }

    std::lock_guard<std::mutex> lck(g_dcmSoMutex);
    std::string funcName(functionName);
    auto it = g_dcmFunctions.find(funcName);
    if (it != g_dcmFunctions.end()) {
        return reinterpret_cast<T>(it->second);
    }
    
    if (g_certMgrSdkHandle == nullptr) {
        g_certMgrSdkHandle = dlopen("libdevice_cert_mgr_sdk.z.so", RTLD_NOW);
        HKS_IF_NULL_LOGE_RETURN(g_certMgrSdkHandle, nullptr, "dlopen failed: %" LOG_PUBLIC "s", dlerror())
    }
    
    void* func = dlsym(g_certMgrSdkHandle, functionName);
    HKS_IF_NULL_LOGE_RETURN(func, nullptr, "dlsym %" LOG_PUBLIC "s failed: %" LOG_PUBLIC "s", functionName, dlerror())
    
    g_dcmFunctions[funcName] = func;
    return reinterpret_cast<T>(func);
}

template AttestFunction HksGetDcmFunction<AttestFunction>(const char* functionName);
template LocalAttestFunction HksGetDcmFunction<LocalAttestFunction>(const char* functionName);

#endif
