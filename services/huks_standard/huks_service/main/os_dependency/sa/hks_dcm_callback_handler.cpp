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

#include "hks_log.h"
#include "hks_sa_interface.h"
#include "hks_template.h"
#include "hks_type.h"
#include "iremote_broker.h"
#include "iremote_object.h"

#define DCM_SDK_SO "libdevice_cert_mgr_sdk.z.so"

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
        if (position != mValues.end()) {
            HKS_LOG_E("SetNewInstance: current value exist requestId = %" LOG_PUBLIC PRIu64, position->second);
            return HKS_ERROR_ALREADY_EXISTS;
        }
        mValues[index] = value;
        return HKS_SUCCESS;
    }
    sptr<IHksService> GetProxyWithoutLock(uint64_t value)
    {
        auto position = findInMapByValue(value);
        if (position == mValues.end()) {
            HKS_LOG_E("GetProxyWithoutLock: current value not exist, requestId %" LOG_PUBLIC PRIu64, value);
            return nullptr;
        }
        return position->first;
    }
    void RemoveWithoutLock(uint64_t value)
    {
        auto position = findInMapByValue(value);
        if (position == mValues.end()) {
            HKS_LOG_E("RemoveWithoutLock: current value not exist, requestId %" LOG_PUBLIC PRIu64, value);
            return;
        }
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
    if (buf->size < sizeof(blob->size) + ALIGN_SIZE(blob->size)) {
        HKS_LOG_E("buf size smaller than blob size");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(buf->data, buf->size, &blob->size, sizeof(blob->size)) != EOK) {
        HKS_LOG_E("copy buf fail");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    buf->data += sizeof(blob->size);
    buf->size -= sizeof(blob->size);
    if (memcpy_s(buf->data, buf->size, blob->data, blob->size) != EOK) {
        HKS_LOG_E("copy buf fail");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    buf->data += ALIGN_SIZE(blob->size);
    buf->size -= ALIGN_SIZE(blob->size);
    return HKS_SUCCESS;
}

int32_t PackAttestChain(struct DcmCertChain *certChain, struct HksBlob *certChainPacked)
{
    if (certChain == nullptr || certChain->certs == nullptr) {
        HKS_LOG_E("certChain buffer from caller is null.");
        return HKS_ERROR_NULL_POINTER;
    }
    if (certChain->certsCount == 0 || certChain->certsCount > HKS_CERT_COUNT) {
        HKS_LOG_E("certs count %" LOG_PUBLIC "u is not correct", certChain->certsCount);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    for (uint32_t i = 0; i < certChain->certsCount; ++i) {
        if (certChain->certs[i].data == nullptr || certChain->certs[i].size == 0 ||
            certChain->certs[i].size > HKS_CERT_APP_SIZE) {
            HKS_LOG_E("cert %" LOG_PUBLIC "u is null or cert size %" LOG_PUBLIC "u invalid ",
                i, certChain->certs[i].size);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    struct HksBlob tmp = *certChainPacked;
    if (tmp.size <= sizeof(uint32_t)) {
        HKS_LOG_E("certChainPacked size too small");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
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
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    certChainPacked->size = tmp.data - certChainPacked->data;
    return HKS_SUCCESS;
}

ThreadSafeMap g_instancesList{};
void *g_certMgrSdkHandle{};
AttestFunction g_attestFunction{};

}}} // OHOS::Security::Hks

using OHOS::Security::Hks::g_instancesList;
using OHOS::Security::Hks::g_certMgrSdkHandle;
using OHOS::Security::Hks::g_attestFunction;
using OHOS::Security::Hks::IHksService;
using OHOS::Security::Hks::PackAttestChain;
using OHOS::sptr;

void HksDcmCallback(DcmAnonymousResponse *response)
{
    if (response == nullptr) {
        HKS_LOG_E("dcm callback got null response");
        return;
    }
    HKS_LOG_I("dcm callback requestId %" LOG_PUBLIC PRIu64, response->requestId);
    std::lock_guard<std::mutex> lockGuard(g_instancesList.GetMutex());
    sptr<IHksService> hksProxy = g_instancesList.GetProxyWithoutLock(response->requestId);
    if (hksProxy == nullptr) {
        HKS_LOG_E("GetProxyWithoutLock failed *requestId %" LOG_PUBLIC PRIu64, response->requestId);
        return;
    }
    std::unique_ptr<uint8_t[]> replyData = nullptr;
    uint32_t replySize = 0;
    do {
        HKS_IF_NOT_SUCC_LOGE_BREAK(response->errCode, "HksDcmCallback failed %" LOG_PUBLIC "d", response->errCode)
        uint32_t packedSize = HKS_CERT_ROOT_SIZE + HKS_CERT_CA_SIZE + HKS_CERT_DEVICE_SIZE + HKS_CERT_APP_SIZE;
        std::unique_ptr<uint8_t[]> packedCertChain(new (std::nothrow) uint8_t[packedSize]());
        HKS_IF_NULL_LOGE_BREAK(packedCertChain, "new cert chain buffer failed")
        HksBlob packedBlob { .size = packedSize, .data = packedCertChain.get() };
        int ret = PackAttestChain(response->certChain, &packedBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "PackAttestChain failed %" LOG_PUBLIC "d", ret)
        replyData = std::move(packedCertChain);
        replySize = packedBlob.size;
    } while (false);
    hksProxy->SendAsyncReply(response->errCode, replyData, replySize);
    g_instancesList.RemoveWithoutLock(response->requestId);
}

int32_t HksDcmCallbackHandlerSetRequestIdWithoutLock(const uint8_t *remoteObject, uint64_t requestId)
{
    auto hksProxy = OHOS::iface_cast<IHksService>(
        reinterpret_cast<OHOS::IRemoteObject *>(const_cast<uint8_t *>(remoteObject)));
    if (hksProxy == nullptr) {
        HKS_LOG_E("iface_cast IHksService failed");
        return HKS_ERROR_NULL_POINTER;
    }
    int ret = g_instancesList.SetNewInstanceWithoutLock(hksProxy, requestId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("g_instancesList.SetNewInstance failed %" LOG_PUBLIC "d", ret);
    }
    return ret;
}

std::mutex &HksDcmCallbackHandlerGetMapMutex(void)
{
    return g_instancesList.GetMutex();
}

AttestFunction HksOpenDcmFunction(void)
{
    if (g_attestFunction != nullptr) {
        return g_attestFunction;
    }

    g_certMgrSdkHandle = dlopen(DCM_SDK_SO, RTLD_NOW);
    if (g_certMgrSdkHandle == nullptr) {
        HKS_LOG_E("dlopen " DCM_SDK_SO " failed! %" LOG_PUBLIC "s", dlerror());
        return nullptr;
    }
    g_attestFunction = reinterpret_cast<AttestFunction>(dlsym(g_certMgrSdkHandle, "DcmAnonymousAttestKey"));
    if (g_attestFunction == nullptr) {
        HKS_LOG_E("dlsym failed %" LOG_PUBLIC "s", dlerror());
        HksCloseDcmFunction();
        return nullptr;
    }
    return g_attestFunction;
}

void HksCloseDcmFunction(void)
{
    if (g_certMgrSdkHandle == nullptr) {
        g_attestFunction = nullptr;
        return;
    }
    int ret = dlclose(g_certMgrSdkHandle);
    if (ret != 0) {
        HKS_LOG_E("dlclose g_certMgrSdkHandle failed %" LOG_PUBLIC "d %" LOG_PUBLIC "s", ret, dlerror());
    }
    g_certMgrSdkHandle = nullptr;
    g_attestFunction = nullptr;
}

#endif // HKS_UNTRUSTED_RUNNING_ENV
