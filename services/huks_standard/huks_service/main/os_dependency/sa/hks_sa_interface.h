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

#ifndef HKS_SA_INTERFACE_H
#define HKS_SA_INTERFACE_H

#include <iremote_broker.h>
#include <iremote_proxy.h>
#include <iremote_stub.h>
#include <memory>

namespace OHOS {
namespace Security {
namespace Hks {
class IHksService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.hks.service");
    virtual void SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz) = 0;
};

class HksStub : public IRemoteStub<IHksService> {
public:
    void SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz) override;
    std::tuple<uint32_t, std::unique_ptr<uint8_t[]>, uint32_t> WaitForAsyncReply(int timeout);
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int ProcessAttestKeyAsyncReply(MessageParcel& data);

    uint32_t mErrCode = 0;
    uint32_t mSize = 0;
    std::unique_ptr<uint8_t[]> mAsyncReply {};

    std::mutex mMutex;
    std::condition_variable mCv;
};

class HksProxy : public IRemoteProxy<IHksService> {
public:
    explicit HksProxy(const sptr<IRemoteObject> &impl);
    ~HksProxy() = default;
    void SendAsyncReply(uint32_t errCode, std::unique_ptr<uint8_t[]> &certChain, uint32_t sz) override;
private:
    static BrokerDelegator<HksProxy> delegator_;
};
} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_SA_INTERFACE_H
