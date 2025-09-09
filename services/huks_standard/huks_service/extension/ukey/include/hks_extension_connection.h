/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef HKS_EXTENSION_CONNECTION_H
#define HKS_EXTENSION_CONNECTION_H

#include <shared_mutex>
#include <string>

#include "ability_connect_callback_stub.h"
#include "singleton.h"
#include "iremote_object.h"
 #include "hks_log.h"
 #include "hks_template.h"


namespace OHOS {
namespace Security {
namespace Huks {

class ExtensionConnection : public AAFwk::AbilityConnectionStub {
public:
    int32_t OnConnection(const Want &want);
    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int resultCode) override;
    void OnDisconnect();
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;
    
    bool IsConnected() const;
    sptr<DesignAccessExtBase> GetExtConnectProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

private: 
    std::condition_variable proxyConv_;
    std::mutex proxyMutex_;
    bool isReady = false;

    std::atomic<bool> isConnected_ = {false}; // 供provider检测连接状态
    std::mutex deathRecipientMutex_;
    sptr<IRemoteObject::DeathRecipient> callerDeathRecipient_ = nullptr;
    sptr<DesignAccessExtBase> extConnectProxy;
    
    void AddExtDeathRecipient(const wptr<IRemoteObject>& token);
    void RemoveExtDeathRecipient(const wptr<IRemoteObject>& token);
};

class ExtensionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit ExtensionDeathRecipient(RemoteDiedHandler &handler);
    virtual ~ExtensionDeathRecipient();
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
private:
    RemoteDiedHandler handler_;
};

}
}
}
#endif