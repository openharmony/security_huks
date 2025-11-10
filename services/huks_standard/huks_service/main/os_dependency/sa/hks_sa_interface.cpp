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
#include "hks_template.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace Hks {

void HksStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    std::unique_lock<std::mutex> lck(mMutex);
    received = true;
    mErrCode = errCode;
    mAsyncReply = std::move(certChain);
    mSize = sz;
    mCv.notify_all();
}

int HksStub::ProcessAttestKeyAsyncReply(MessageParcel& data)
{
    std::unique_ptr<uint8_t[]> certChain{};
    uint32_t errCode = 1;
    if (!data.ReadUint32(errCode) || errCode != DCM_SUCCESS) {
        HKS_LOG_E("ipc client read errCode %" LOG_PUBLIC "u", errCode);
        SendAsyncReply(errCode, certChain, 0);
        return ERR_INVALID_DATA;
    }
    uint32_t certChainLen = 0;
    int err = ERR_INVALID_DATA;
    do {
        uint32_t sz = 0;
        HKS_IF_TRUE_LOGE_BREAK(!data.ReadUint32(sz) || sz == 0 || sz > MAX_OUT_BLOB_SIZE,
            "invalid sz %" LOG_PUBLIC "u", sz)
        const uint8_t *ptr = data.ReadBuffer(sz);
        HKS_IF_NULL_LOGE_BREAK(ptr, "ReadBuffer %" LOG_PUBLIC "u size ptr is nullptr", sz)
        auto receivedPtr = std::make_unique<uint8_t[]>(sz);
        if (receivedPtr == nullptr) {
            HKS_LOG_E("new receivedPtr failed");
            err = ERR_NO_MEMORY;
            break;
        }
        HKS_IF_NOT_EOK_LOGE_BREAK(memcpy_s(receivedPtr.get(), sz, ptr, sz), "memcpy_s receivedPtr failed");
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
    HKS_IF_TRUE_LOGE_RETURN(data.ReadInterfaceToken() != GetDescriptor(), ERR_INVALID_DATA,
        "failed to check interface token! code %" LOG_PUBLIC "d", code)
    HKS_IF_TRUE_LOGE_RETURN(code != HKS_MSG_ATTEST_KEY_ASYNC_REPLY, ERR_TRANSACTION_FAILED,
        "unknown remote request code %" LOG_PUBLIC "u", code)
    return ProcessAttestKeyAsyncReply(data);
}

std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t> HksStub::WaitForAsyncReply(int timeout)
{
    std::unique_lock<std::mutex> lck(mMutex);
    if (received) {
        return {mErrCode, std::move(mAsyncReply), mSize};
    }
    mAsyncReply = nullptr;
    mSize = 0;
    mErrCode = DCM_SUCCESS;
    HKS_LOG_I("begin wait for async reply");
    if (mCv.wait_for(lck, std::chrono::seconds(timeout)) == std::cv_status::timeout) {
        HKS_LOG_E("WaitForAsyncReply timeout! %d seconds", timeout);
        return {HKS_ERROR_BAD_STATE, nullptr, 0};
    }
    return {mErrCode, std::move(mAsyncReply), mSize};
}

BrokerDelegator<HksProxy> HksProxy::delegator_;
HksProxy::HksProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksService>(impl)
{
}

void HksProxy::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(Remote(), "Remote() is nullptr! Would not SendRequest!")
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_ASYNC;
    bool writeResult = data.WriteInterfaceToken(GetDescriptor());
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult,
        "WriteInterfaceToken errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", errCode, writeResult)
    writeResult = data.WriteUint32(errCode);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        errCode, writeResult)
    if (errCode != DCM_SUCCESS) {
        HKS_LOG_E("dcm callback fail errCode %" LOG_PUBLIC "u", errCode);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK, "send fail reply errCode failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteUint32(sz);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 sz %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sz, writeResult)
    if (sz == 0 || certChain == nullptr) {
        HKS_LOG_E("dcm reply success but empty certChain %" LOG_PUBLIC "u", sz);
        int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK,
            "Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteBuffer(certChain.get(), sz);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteBuffer size %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sz, writeResult)
    int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_IF_TRUE_LOGE(res != ERR_OK,
        "Remote()->SendRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY failed %" LOG_PUBLIC "d", res)
}

void HksExtStub::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &sendData, uint32_t sendSize,
    uint32_t msgCode)
{
    std::unique_lock<std::mutex> lck(mMutex);
    received = true;
    mErrCode = errCode;
    mMsgCode = msgCode;
    mAsyncReply = std::move(sendData);
    mSize = sendSize;
    mCv.notify_all();
}

int HksExtStub::ProcessExtGetRemotePropertyReply(MessageParcel& data)
{
    std::unique_ptr<uint8_t[]> receivedData{};
    uint32_t errCode = 1;
    if (!data.ReadUint32(errCode) || errCode != HKS_SUCCESS) {
        HKS_LOG_E("ipc client read errCode %" LOG_PUBLIC "u", errCode);
        SendAsyncReply(errCode, receivedData, 0, HKS_MSG_EXT_GET_REMOTE_PROPERTY_REPLY);
        return ERR_INVALID_DATA;
    }
    uint32_t receivedSize = 0;
    int err = ERR_INVALID_DATA;
    do {
        uint32_t size = 0;
        HKS_IF_TRUE_LOGE_BREAK(!data.ReadUint32(size) || size == 0 || size > MAX_OUT_BLOB_SIZE,
            "invalid size %" LOG_PUBLIC "u", size)
        const uint8_t *ptr = data.ReadBuffer(size);
        HKS_IF_NULL_LOGE_BREAK(ptr, "ReadBuffer %" LOG_PUBLIC "u size ptr is nullptr", size)
        auto receivedPtr = std::make_unique<uint8_t[]>(size);
        if (receivedPtr == nullptr) {
            HKS_LOG_E("new receivedPtr failed");
            err = ERR_NO_MEMORY;
            break;
        }
        HKS_IF_NOT_EOK_LOGE_BREAK(memcpy_s(receivedPtr.get(), size, ptr, size), "memcpy_s receivedPtr failed");
        err = ERR_OK;
        receivedData = std::move(receivedPtr);
        receivedSize = size;
    } while (false);
    SendAsyncReply(errCode, receivedData, receivedSize, HKS_MSG_EXT_GET_REMOTE_PROPERTY);
    return err;
}

std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t, uint32_t> HksExtStub::WaitForAsyncReply(int timeout)
{
    std::unique_lock<std::mutex> lck(mMutex);
    if (received) {
        return {mErrCode, std::move(mAsyncReply), mSize, mMsgCode};
    }
    mAsyncReply = nullptr;
    mSize = 0;
    mMsgCode = 0;
    mErrCode = HKS_SUCCESS;
    HKS_LOG_I("begin wait for async reply");
    if (mCv.wait_for(lck, std::chrono::seconds(timeout)) == std::cv_status::timeout) {
        HKS_LOG_E("WaitForAsyncReply timeout! %" LOG_PUBLIC "u seconds", timeout);
        return {HKS_ERROR_BAD_STATE, nullptr, 0, 0};
    }
    return {mErrCode, std::move(mAsyncReply), mSize, mMsgCode};
}

int HksExtStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    (void)reply;
    (void)option;
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        return ERR_INVALID_DATA;
    }
    switch (code) {
        case HKS_MSG_EXT_GET_REMOTE_PROPERTY_REPLY:
            return ProcessExtGetRemotePropertyReply(data);
        default:
            HKS_LOG_E("OnRemoteRequest unexpected code %" LOG_PUBLIC "u", code);
            return ERR_TRANSACTION_FAILED;
    }
}

BrokerDelegator<HksExtProxy> HksExtProxy::delegator_;
HksExtProxy::HksExtProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksExtService>(impl)
{
}

void HksExtProxy::SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &sendData, uint32_t sendSize,
    uint32_t msgCode)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(Remote(), "Remote() is nullptr! Would not SendRequest!")
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_ASYNC;
    bool writeResult = data.WriteInterfaceToken(GetDescriptor());
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult,
        "WriteInterfaceToken errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d", errCode, writeResult)
    writeResult = data.WriteUint32(errCode);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 errCode %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        errCode, writeResult)
    if (errCode != HKS_SUCCESS) {
        HKS_LOG_E("ukey callback fail errCode %" LOG_PUBLIC "u", errCode);
        int res = Remote()->SendRequest(msgCode, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK, "send fail reply errCode failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteUint32(sendSize);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteUint32 sendSize %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sendSize, writeResult)
    if (sendSize == 0 || sendData == nullptr) {
        HKS_LOG_E("ukey reply success but empty sendData %" LOG_PUBLIC "u", sendSize);
        int res = Remote()->SendRequest(msgCode, data, reply, option);
        HKS_IF_TRUE_LOGE(res != ERR_OK,
            "Remote()->SendRequest failed %" LOG_PUBLIC "d", res)
        return;
    }
    writeResult = data.WriteBuffer(sendData.get(), sendSize);
    HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(writeResult, "WriteBuffer size %" LOG_PUBLIC "u failed %" LOG_PUBLIC "d",
        sendSize, writeResult)
    int res = Remote()->SendRequest(msgCode, data, reply, option);
    HKS_IF_TRUE_LOGE(res != ERR_OK,
        "Remote()->SendRequest failed %" LOG_PUBLIC "d", res)
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
 