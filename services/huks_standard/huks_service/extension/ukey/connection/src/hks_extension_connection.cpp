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

#include "hks_extension_connection.h"
#include "ability_manager_client.h"
#include "hks_log.h"
#include "hks_template.h"
#include "huks_access_ext_base_proxy.h"

namespace OHOS {
namespace Security {
namespace Huks {

constexpr int WAIT_TIME = 3;
constexpr int32_t DEFAULT_USER_ID = 100;

void ExtensionConnection::OnAbilityConnectDone(const OHOS::AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HKS_IF_TRUE_RETURN_VOID(remoteObject == nullptr)

    extConnectProxy = iface_cast<HuksAccessExtBaseProxy>(remoteObject);
    HKS_IF_TRUE_RETURN_VOID(extConnectProxy == nullptr)

    AddExtDeathRecipient(extConnectProxy->AsObject());
    std::lock_guard<std::mutex> lock(proxyMutex_);
    isConnected_.store(true);
    isReady = true;
    proxyConv_.notify_all();
}

int32_t ExtensionConnection::OnConnection(const AAFwk::Want &want)
{
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, this, DEFAULT_USER_ID);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_EXEC_FUNC_FAIL,
        "fail to connect ability by ability manager service")

    std::unique_lock<std::mutex> lock(proxyMutex_);
    if (!proxyConv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [this] {
        return extConnectProxy != nullptr && isReady;
    })) {
        HKS_LOG_E("wait connect timeout");
        return HKS_ERROR_CONNECT_TIME_OUT;
    }
    return HKS_SUCCESS;
}

void ExtensionConnection::OnDisconnect()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    if (extConnectProxy != nullptr) {
        RemoveExtDeathRecipient(extConnectProxy->AsObject());
    }
    extConnectProxy = nullptr;
    isConnected_.store(false);
    isReady = false;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(this);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "disconnect ability fail, ret = %{public}d", ret)
}

void ExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    extConnectProxy = nullptr;
    isConnected_.store(false);
    isReady = false;
}

sptr<IHuksAccessExtBase> ExtensionConnection::GetExtConnectProxy()
{
    return extConnectProxy;
}

bool ExtensionConnection::IsConnected()
{
    return isConnected_.load();
}

void ExtensionConnection::AddExtDeathRecipient(const wptr<IRemoteObject>& token)
{
    std::unique_lock<std::mutex> lock(deathRecipientMutex_);
    if (token != nullptr && callerDeathRecipient_ != nullptr) {
        token->RemoveDeathRecipient(callerDeathRecipient_);
    }

    if (callerDeathRecipient_ == nullptr) {
        callerDeathRecipient_ = new ExtensionDeathRecipient(std::bind(&ExtensionConnection::OnRemoteDied,
            this, std::placeholders::_1));
    }

    if (token != nullptr) {
        token->AddDeathRecipient(callerDeathRecipient_);
    }
}

void ExtensionConnection::RemoveExtDeathRecipient(const wptr<IRemoteObject>& token)
{
    std::unique_lock<std::mutex> lock(deathRecipientMutex_);
    if (token != nullptr && callerDeathRecipient_ != nullptr) {
        token->RemoveDeathRecipient(callerDeathRecipient_);
    }
}

void ExtensionConnection::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    HKS_LOG_E("OnRemoteDied from ExtensionConnection");
    auto object = remote.promote();
    if (object) {
        object = nullptr;
    }
    isConnected_.store(false);
    isReady = false;
    if (extConnectProxy) {
        extConnectProxy = nullptr;
    }
}

ExtensionDeathRecipient::ExtensionDeathRecipient(RemoteDiedHandler handler) : handler_(handler)
{
}

ExtensionDeathRecipient::~ExtensionDeathRecipient()
{
}

void ExtensionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HKS_LOG_E("OnRemoteDied from ExtensionDeathRecipient");
    if (handler_) {
        handler_(remote);
    }
}

}
}
}

