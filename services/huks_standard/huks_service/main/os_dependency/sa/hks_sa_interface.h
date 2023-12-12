#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Security {
namespace Hks {
class IHksService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.hks.service");
    virtual void SendAsyncReply(int &reply) = 0;
};

class HksStub : public IRemoteStub<IHksService> {
public:
    void SendAsyncReply(int &reply) override;
    int WaitForAsyncReply(int timeout);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int asyncReply_ = { 0 };
    std::mutex mutex_;
    std::condition_variable cv_;
};

class HksProxy : public IRemoteProxy<IHksService> {
public:
    explicit HksProxy(const sptr<IRemoteObject> &impl);
    ~HksProxy() = default;
    void SendAsyncReply(int &reply) override;
private:
    static BrokerDelegator<HksProxy> delegator_;
}; 
} // namespace Hks
} // namespace Security
} // namespace OHOS
