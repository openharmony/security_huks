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

#ifndef HKS_SA_H
#define HKS_SA_H

#include "huks_service_ipc_interface_code.h"
#include "hks_sa_interface.h"

#include <atomic>
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "system_ability.h"

namespace OHOS {
namespace Security {
namespace Hks {
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};
enum ResponseCode {
    HW_NO_ERROR =  0,
    HW_SYSTEM_ERROR = -1,
    HW_PERMISSION_DENIED = -2,
};

constexpr int SA_ID_KEYSTORE_SERVICE = 3510;

class HksService : public SystemAbility, public HksStub {
    DECLEAR_SYSTEM_ABILITY(HksService)

public:
    DISALLOW_COPY_AND_MOVE(HksService);
    HksService(int saId, bool runOnCreate);
    virtual ~HksService();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    static sptr<HksService> GetInstance();

protected:
    void OnStart() override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnStop() override;

private:
    HksService();
    bool Init();

    bool registerToService_;
    volatile std::atomic_int runningState_;
    std::mutex runningStateLock;
    static std::mutex instanceLock;
    static sptr<HksService> instance;
    int OnRemotePluginRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};

class HksDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit HksDeathRecipient(int32_t callingPid, int32_t callingUid);
    ~HksDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remoteObject) override;
private:
    void NotifyExtOnBinderDied(int32_t pid);
    int32_t callingUid_;
    int32_t callingPid_;
};

} // namespace Hks
} // namespace Security
} // namespace OHOS

#endif // HKS_SA_H
