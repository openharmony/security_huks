#include "hks_sa_interface.h"
#include "hks_log.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace Hks {

void HksStub::SendAsyncReply(int &replyValue)
{
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called", __PRETTY_FUNCTION__, __LITE__);
    std::unique_lock<std::mutex> lck(mutex_);
    asyncReply_ = replyValue;
    cv_.notify_all();
}

int HksStub::OnRemoteRequest(uint32_t code,
    MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called code = %" LOG_PUBLIC "d", __PRETTY_FUNCTION__, __LITE__, code);
    int result = ERR_NONE;

    switch (code) {
        case HKS_MSG_ATTEST_KEY_ASYNC_REPLY: {
            int32_t replyData = data.ReadInt32();
            HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called replyData = %" LOG_PUBLIC "d", __PRETTY_FUNCTION__, __LITE__, replyData);
            SendAsyncReply(replyData);
            break;
        }
        default:
            result = ERR_TRANSACTION_FAILED;
            break;
    }

    return result;
}

int HksStub::WaitForAsyncReply(int timeout)
{
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called", __PRETTY_FUNCTION__, __LITE__);
    asyncReply_ = 0;
    std::unique_lock<std::mutex> lck(mutex_);
    cv_.wait_for(lck, std::chrono::seconds(timeout), [this]() {
        return asyncReply_ != 0;
    });
    return asyncReply_;
}

BrokerDelegator<HksProxy> HksProxy::delegator_;
HksProxy::HksProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IHksService>(impl)
{
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called", __PRETTY_FUNCTION__, __LITE__);
}

void HksProxy::SendAsyncReply(int &replyValue)
{
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d:called", __PRETTY_FUNCTION__, __LITE__);
    MessageParcel data, reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    data.WriteInt32(replyValue);
    int res = Remote()->SendRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
    HKS_LOG_I("%" LOG_PUBLIC "s:%" LOG_PUBLIC "d: res = %" LOG_PUBLIC "d:", __PRETTY_FUNCTION__, __LITE__, res);
}

} // namespace Hks
} // namespace Security
} // namespace OHOS
