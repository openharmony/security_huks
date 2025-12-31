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
#include <securec.h>
#include "ability_connect_callback_stub.h"
#include "iremote_object.h"
#include "ihuks_access_ext_base.h"
#include "want.h"
#include "functional"
#include "hks_plugin_def.h"

namespace OHOS {
namespace Security {
namespace Huks {

class ExtensionConnection : public OHOS::AAFwk::AbilityConnectionStub {
public:
    ExtensionConnection(const HksProcessInfo &info);
    int32_t OnConnection(const AAFwk::Want &want, sptr<ExtensionConnection> &connect, int32_t userid);
    void OnAbilityConnectDone(const AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& remoteObject, int resultCode) override;
    void OnDisconnect(sptr<ExtensionConnection> &connect);
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;
    bool IsConnected();
    sptr<IHuksAccessExtBase> GetExtConnectProxy();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);
    bool isDeathRemoted = false;
    std::function<void(HksProcessInfo)> callBackPlugin;
    void callBackFromPlugin(std::function<void(HksProcessInfo)> callback);
    HksProcessInfo m_processInfo;
private:
    std::condition_variable proxyConv_{};
    std::condition_variable disConnectConv_{};
    std::mutex proxyMutex_{};
    std::atomic<bool> isConnected_ = {false};
    sptr<IRemoteObject::DeathRecipient> callerDeathRecipient_{nullptr};
    sptr<IHuksAccessExtBase> extConnectProxy{};
    void AddExtDeathRecipient(const wptr<IRemoteObject>& token);
    void RemoveExtDeathRecipient(const wptr<IRemoteObject>& token);
};

class ExtensionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    explicit ExtensionDeathRecipient(RemoteDiedHandler handler);
    virtual ~ExtensionDeathRecipient();
    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
private:
    RemoteDiedHandler handler_;
};

}
}
}
#endif