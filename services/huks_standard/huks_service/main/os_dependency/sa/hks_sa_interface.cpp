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

#include "hks_sa_interface.h"

#include <errors.h>
#include <ipc_types.h>
#include <memory>
#include <mutex>
#include <securec.h>

#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace Hks {

void HksStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    std::unique_lock<std::mutex> lck(mMutex);
    mErrCode = errCode;
    mAsyncReply = std::move(certChain);
    mSize = sz;
    mCv.notify_all();
}

int HksStub::ProcessAttestKeyAsyncReply(MessageParcel& data)
{
    std::unique_ptr<uint8_t[]> certChain{};
    uint32_t errCode = data.ReadUint32();
    if (errCode != DCM_SUCCESS) {
        HKS_LOG_E("ipc client read errCode %" LOG_PUBLIC "u", errCode);
        SendAsyncReply(errCode, certChain, 0);
        return ERR_INVALID_DATA;
    }
    uint32_t certChainLen = 0;
    int err = ERR_INVALID_DATA;
    do {
        uint32_t sz = data.ReadUint32();
        if (sz == 0) {
            HKS_LOG_E("sz is 0");
            break;
        }
        const uint8_t *ptr = data.ReadBuffer(sz);
        if (ptr == nullptr) {
            HKS_LOG_E("ReadBuffer %" LOG_PUBLIC "u size ptr is nullptr", sz);
            break;
        }
        std::unique_ptr<uint8_t[]> receivedPtr(new (std::nothrow) uint8_t[sz]());
        if (receivedPtr == nullptr) {
            HKS_LOG_E("new receivedPtr failed");
            err = ERR_NO_MEMORY;
            break;
        }
        errno_t err = memcpy_s(receivedPtr.get(), sz, ptr, sz);
        if (err != EOK) {
            HKS_LOG_E("memcpy_s receivedPtr failed");
            break;
        }
        err = ERR_OK;
        certChain = std::move(receivedPtr);
        certChainLen = sz;
    } while (false);
    SendAsyncReply(errCode, certChain, certChainLen);
    return err;
}

int HksStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    int result = ERR_NONE;

    switch (code) {
        case HKS_MSG_ATTEST_KEY_ASYNC_REPLY:
            result = ProcessAttestKeyAsyncReply(data);
            break;
        default:
            HKS_LOG_E("unknown remote request code %" LOG_PUBLIC "u", code);
            result = ERR_TRANSACTION_FAILED;
            break;
    }

    return result;
}

std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t> HksStub::WaitForAsyncReply(int timeout)
{
    std::unique_lock<std::mutex> lck(mMutex);
    mAsyncReply = nullptr;
    mSize = 0;
    mErrCode = DCM_SUCCESS;
    HKS_LOG_I("begin wait for async reply");
    mCv.wait_for(lck, std::chrono::seconds(timeout));
    return {mErrCode, std::move(mAsyncReply), mSize};
}

BrokerDelegator<HksProxy> HksProxy::delegator_;
HksProxy::HksProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksService>(impl)
{
}

void HksProxy::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    if (Remote() == nullptr) {
        HKS_LOG_E("Remote() is nullptr! Would not SendRequest!");
        return;
    }
    MessageParcel data, reply;
    MessageOption option = MessageOption::TF_ASYNC;
    bool writeResult = data.WriteUint32(errCode);
    if (!writeResult) {
        HKS_LOG_E("WriteUint32 errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", errCode, writeResult);
        return;
    }
    if (errCode != DCM_SUCCESS) {
        HKS_LOG_E("dcm callback fail errCode %" LOG_PUBLIC "u", errCode);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        if (res != ERR_OK) {
            HKS_LOG_E("send fail reply errCode failed %" LOG_PUBLIC "d", res);
        }
        return;
    }
    writeResult = data.WriteUint32(sz);
    if (!writeResult) {
        HKS_LOG_E("WriteUint32 sz %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", sz, writeResult);
        return;
    }
    if (sz == 0 || certChain == nullptr) {
        HKS_LOG_E("dcm reply success but empty certChain %" LOG_PUBLIC "u", sz);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        if (res != ERR_OK) {
            HKS_LOG_E("Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res);
        }
        return;
    }
    writeResult = data.WriteBuffer(certChain.get(), sz);
    if (!writeResult) {
        HKS_LOG_E("WriteBuffer size %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", sz, writeResult);
        return;
    }
    int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    if (res != ERR_OK) {
        HKS_LOG_E("Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res);
    }
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
