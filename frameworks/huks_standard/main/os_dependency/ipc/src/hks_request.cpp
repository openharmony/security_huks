/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hks_request.h"

#include <iservice_registry.h>
#include <message_option.h>
#include <securec.h>

#include "hks_base_check.h" // for HksAttestIsAnonymous
#include "hks_log.h"
#include "hks_param.h"
#include "hks_sa_interface.h"
#include "hks_template.h"
#include "hks_type.h"
#include "huks_service_ipc_interface_code.h"

using namespace OHOS;

namespace {
constexpr int SA_ID_KEYSTORE_SERVICE = 3510;
const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.hks.service";
static volatile std::atomic_bool g_isInitBundleDead = false;
sptr<Security::Hks::HksStub> g_hks_callback;
}

struct HksExtAsyncCtx {
    MessageParcel *data {};
    const HksParamSet *paramSet {};
    sptr<IRemoteObject> hksProxy;
    sptr<Security::Hks::HksExtStub> hksCallback;
    HksBlob *outBlob {};
    uint32_t msgCode {};
};

static sptr<IRemoteObject> GetHksProxy()
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    HKS_IF_NULL_LOGE_RETURN(registry, nullptr, "GetHksProxy registry is null")

    sptr<IRemoteObject> hksProxy = registry->GetSystemAbility(SA_ID_KEYSTORE_SERVICE);
    HKS_IF_NULL_LOGE_RETURN(hksProxy, nullptr,
        "GetHksProxy GetSystemAbility %" LOG_PUBLIC "d is null", SA_ID_KEYSTORE_SERVICE)

    return hksProxy;
}

static int32_t HksReadRequestReply(MessageParcel &reply, struct HksBlob *outBlob)
{
    int32_t ret = reply.ReadInt32();

    uint32_t outLen = reply.ReadUint32();
    if (ret == HKS_SUCCESS && outLen == 0) {
        if (outBlob != nullptr) {
            outBlob->size = 0;
        }
    }
    if (outLen != 0) {
        HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(outBlob), (ret == HKS_SUCCESS ? HKS_ERROR_INVALID_ARGUMENT : ret),
            "Check blob failed in HksReadRequestReply")
        const uint8_t *outData = reply.ReadBuffer(outLen);
        HKS_IF_NULL_RETURN(outData, ret == HKS_SUCCESS ? HKS_ERROR_IPC_MSG_FAIL : ret)

        if (ret == HKS_SUCCESS) {
            if (outBlob->size < outLen) {
                HKS_LOG_E("outBlob size[%" LOG_PUBLIC "u] smaller than outLen[%" LOG_PUBLIC "u]",
                    outBlob->size, outLen);
                return (ret == HKS_SUCCESS) ? HKS_ERROR_BUFFER_TOO_SMALL : ret;
            }
            HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(outBlob->data, outBlob->size, outData, outLen),
                ret == HKS_SUCCESS ? HKS_ERROR_INSUFFICIENT_MEMORY : ret, "copy outBlob data failed!")
            outBlob->size = outLen;
        }
    }
#ifdef L2_STANDARD
    uint32_t errMsgLen = 0;
    if (reply.ReadUint32(errMsgLen) && errMsgLen != 0 && errMsgLen < MAX_ERROR_MESSAGE_LEN) {
        HKS_LOG_D("reply get errMsgLen = %{public}u", errMsgLen);
        const uint8_t *errMsg = reply.ReadUnpadBuffer(errMsgLen);
        HKS_IF_NULL_LOGE_RETURN(errMsg, ret, "[ipc error] read errorMsg")
        HksAppendThreadErrMsg(errMsg, errMsgLen);
    }
#endif

    return ret;
}

static int32_t HksSendAnonAttestRequestAndWaitAsyncReply(MessageParcel &data, const struct HksParamSet *paramSet,
    sptr<IRemoteObject> hksProxy, sptr<Security::Hks::HksStub> hksCallback, struct HksBlob *outBlob)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(outBlob), HKS_ERROR_INVALID_ARGUMENT, "invalid outBlob");
    MessageParcel reply{};
    // We send the request in sync mode, and we send a stub instance in the request.
    // We wait for the instance callback later.
    MessageOption option = MessageOption::TF_SYNC;
    int error = hksProxy->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_IF_NOT_SUCC_LOGE_RETURN(error, HKS_ERROR_IPC_MSG_FAIL, "hksProxy->SendRequest failed %" LOG_PUBLIC "d", error);

    int ret = HksReadRequestReply(reply, outBlob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret,
        "HksSendAnonAttestRequestAndWaitAsyncReply HksReadRequestReply failed %" LOG_PUBLIC "d", ret)

#ifndef HKS_UNTRUSTED_RUNNING_ENV
    int timeout = 10; // seconds
    auto [errCode, packedCerts, packedSize] = hksCallback->WaitForAsyncReply(timeout);
    if (errCode != HKS_SUCCESS || packedCerts == nullptr || packedSize == 0) {
        HKS_LOG_E("errCode %" LOG_PUBLIC "u fail or packedCerts empty or size %" LOG_PUBLIC "u 0", errCode, packedSize);
        return HUKS_ERR_CODE_EXTERNAL_ERROR;
    }

    if (outBlob->size < packedSize) {
        HKS_LOG_E("out blob empty or too small %" LOG_PUBLIC "u %" LOG_PUBLIC "u", outBlob->size, packedSize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(outBlob->data, outBlob->size, packedCerts.get(), packedSize),
        HKS_ERROR_INVALID_ARGUMENT, "memcpy_s failed destMax %" LOG_PUBLIC "u count %" LOG_PUBLIC "u",
        outBlob->size, packedSize)
    outBlob->size = packedSize;
    return HKS_SUCCESS;
#else
    (void)(paramSet);
    (void)(hksCallback);
    return ret;
#endif
}

static int32_t HksExtSendAsyncMessage(const HksExtAsyncCtx &ctx)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckBlob(ctx.outBlob), HKS_ERROR_INVALID_ARGUMENT, "invalid outBlob");

    MessageParcel reply {};
    MessageOption option = MessageOption::TF_SYNC;
    int ret = ctx.hksProxy->SendRequest(ctx.msgCode, *ctx.data, reply, option);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_IPC_MSG_FAIL, "SendRequest failed %" LOG_PUBLIC "d", ret);

    int timeout = 2; // default seconds
    struct HksParam *timeoutParam = nullptr;
    if (HksGetParam(ctx.paramSet, HKS_EXT_CRYPTO_TAG_TIMEOUT, &timeoutParam) == HKS_SUCCESS) {
        if (GetTagType((enum HksTag)timeoutParam->tag) == HKS_TAG_TYPE_UINT && timeoutParam->uint32Param > 0) {
            timeout = timeoutParam->uint32Param;
        }
    }

    auto [errCode, receivedData, receivedSize, receivedCode] = ctx.hksCallback->WaitForAsyncReply(timeout);
    if (errCode != HKS_SUCCESS || receivedData == nullptr || receivedSize == 0 || receivedCode != ctx.msgCode) {
        HKS_LOG_E("async fail errCode=%" LOG_PUBLIC "u size=%" LOG_PUBLIC "u code=%" LOG_PUBLIC "u",
            errCode, receivedSize, receivedCode);
        return HUKS_ERR_CODE_EXTERNAL_ERROR;
    }

    HKS_IF_TRUE_LOGE_RETURN(ctx.outBlob->size < receivedSize, HKS_ERROR_BUFFER_TOO_SMALL,
        "outBlob too small %" LOG_PUBLIC "u < %" LOG_PUBLIC "u", ctx.outBlob->size, receivedSize);

    HKS_IF_NOT_EOK_LOGE_RETURN(memcpy_s(ctx.outBlob->data, ctx.outBlob->size, receivedData.get(), receivedSize),
        HKS_ERROR_INSUFFICIENT_MEMORY, "memcpy_s failed destMax %" LOG_PUBLIC "u count %" LOG_PUBLIC "u",
        ctx.outBlob->size, receivedSize);

    ctx.outBlob->size = receivedSize;
    return HKS_SUCCESS;
}

static int32_t WriteCommonRequestData(MessageParcel &data,
    const struct HksBlob *inBlob, const struct HksBlob *outBlob)
{
    HKS_IF_NOT_TRUE_RETURN(data.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR), HKS_ERROR_BAD_STATE);
    if (outBlob == nullptr) {
        HKS_IF_NOT_TRUE_RETURN(data.WriteUint32(0), HKS_ERROR_BAD_STATE);
    } else {
        HKS_IF_NOT_TRUE_LOGE_RETURN(data.WriteUint32(outBlob->size), HKS_ERROR_BAD_STATE, "WriteUint32 fail");
    }
    HKS_IF_NOT_TRUE_RETURN(data.WriteUint32(inBlob->size), HKS_ERROR_BAD_STATE);
    HKS_IF_NOT_TRUE_RETURN(data.WriteBuffer(inBlob->data, static_cast<size_t>(inBlob->size)), HKS_ERROR_BAD_STATE);
    return HKS_SUCCESS;
}

static int32_t HandleSpecialAsyncTypes(enum HksIpcInterfaceCode type, MessageParcel &data,
    const struct HksParamSet *paramSet, sptr<IRemoteObject> &proxy, struct HksBlob *outBlob)
{
    if (type == HKS_MSG_ATTEST_KEY_ASYNC_REPLY) {
        auto hksCallback = sptr<Security::Hks::HksStub>(new (std::nothrow) Security::Hks::HksStub());
        HKS_IF_NULL_LOGE_RETURN(hksCallback, HKS_ERROR_INSUFFICIENT_MEMORY, "new HksStub failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN(data.WriteRemoteObject(hksCallback), HKS_ERROR_IPC_MSG_FAIL,
            "WriteRemoteObject fail");
        return HksSendAnonAttestRequestAndWaitAsyncReply(data, paramSet, proxy, hksCallback, outBlob);
    }
    if (type == HKS_MSG_EXT_GET_REMOTE_PROPERTY) {
        auto hksCallback = sptr<Security::Hks::HksExtStub>(new (std::nothrow) Security::Hks::HksExtStub());
        HKS_IF_NULL_LOGE_RETURN(hksCallback, HKS_ERROR_INSUFFICIENT_MEMORY, "new HksExtStub failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN(data.WriteRemoteObject(hksCallback), HKS_ERROR_IPC_MSG_FAIL,
            "WriteRemoteObject fail");
        HksExtAsyncCtx ctx { &data, paramSet, proxy, hksCallback, outBlob, HKS_MSG_EXT_GET_REMOTE_PROPERTY };
        return HksExtSendAsyncMessage(ctx);
    }
    return HKS_SUCCESS;
}

int32_t HksSendRequest(enum HksIpcInterfaceCode type, const struct HksBlob *inBlob,
    struct HksBlob *outBlob, const struct HksParamSet *paramSet)
{
#ifdef L2_STANDARD
    HksClearThreadErrorMsg();
#endif
    struct HksParam *sendTypeParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_IS_ASYNCHRONIZED, &sendTypeParam);
    enum HksSendType sendType = (ret == HKS_SUCCESS) ? static_cast<enum HksSendType>(sendTypeParam->uint32Param)
        : HKS_SEND_TYPE_SYNC;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option((sendType == HKS_SEND_TYPE_SYNC) ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC);
    ret = WriteCommonRequestData(data, inBlob, outBlob);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("WriteCommonRequestData failed %" LOG_PUBLIC "d", ret);
        return ret;
    }

    sptr<IRemoteObject> proxy = GetHksProxy();
    HKS_IF_NULL_LOGE_RETURN(proxy, HKS_ERROR_BAD_STATE, "GetHksProxy null");

    bool flag = false;
    if (type == HKS_MSG_INIT && std::atomic_compare_exchange_strong(&g_isInitBundleDead, &flag, true)) {
        g_hks_callback = new (std::nothrow) Security::Hks::HksStub();
        HKS_IF_NULL_LOGE_RETURN(g_hks_callback, HKS_ERROR_INSUFFICIENT_MEMORY, "new HksStub failed");
        HKS_IF_NOT_TRUE_LOGE_RETURN(data.WriteRemoteObject(g_hks_callback), HKS_ERROR_IPC_MSG_FAIL,
            "WriteRemoteObject fail");
    }

    ret = HandleSpecialAsyncTypes(type, data, paramSet, proxy, outBlob);
    if (ret != HKS_SUCCESS || type == HKS_MSG_ATTEST_KEY_ASYNC_REPLY || type == HKS_MSG_EXT_GET_REMOTE_PROPERTY)
        return ret;

    int error = proxy->SendRequest(type, data, reply, option);
    HKS_IF_TRUE_LOGE_RETURN(error != 0, HKS_ERROR_IPC_MSG_FAIL, "SendRequest failed %" LOG_PUBLIC "d", error);
    return HksReadRequestReply(reply, outBlob);
}