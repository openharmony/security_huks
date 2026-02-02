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
#include "hks_ability_manager_service_connection.h"
#include "ability_manager_client.h"
#include "hks_log.h"
#include "hks_template.h"
#include "huks_access_ext_base_proxy.h"

namespace OHOS {
namespace Security {
namespace Huks {

constexpr int WAIT_TIME = 3;

void ExtensionConnection::OnAbilityConnectDone(const OHOS::AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HKS_IF_TRUE_RETURN_VOID(remoteObject == nullptr)

    std::lock_guard<std::mutex> lock(proxyMutex_);
    extConnectProxy = CastToHuksAccessExtBaseProxy(remoteObject);
    HKS_IF_TRUE_LOGE_RETURN_VOID(extConnectProxy == nullptr, "iface_cast fail in OnAbilityConnectDone")

    AddExtDeathRecipient(extConnectProxy->AsObject());
    isConnected_.store(true);
    proxyConv_.notify_all();
}

int32_t ExtensionConnection::OnConnection(const AAFwk::Want &want, sptr<ExtensionConnection> &connect, int32_t userid)
{
    int32_t ret = AMSConnectAbility(want, connect, userid);
    HKS_IF_TRUE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_REMOTE_OPERATION_FAILED)
    
    std::unique_lock<std::mutex> lock(proxyMutex_);
    if (!proxyConv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [this] {
        return extConnectProxy != nullptr;
    })) {
        HKS_LOG_E("wait connected timeout");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    return HKS_SUCCESS;
}

void ExtensionConnection::OnDisconnect(sptr<ExtensionConnection> &connect)
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    if (extConnectProxy != nullptr) {
        RemoveExtDeathRecipient(extConnectProxy->AsObject());
    }

    AMSDisconnectAbility(connect);
    if (!disConnectConv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [connect] {
        HKS_IF_TRUE_LOGE(connect->extConnectProxy == nullptr, "proxy is null, not need to wait!")
        return connect->extConnectProxy == nullptr;
    })) {
        HKS_LOG_E("wait disconnected timeout, or not need to wait");
    };
    extConnectProxy = nullptr;
    isConnected_.store(false);
}

void ExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    extConnectProxy = nullptr;
    isConnected_.store(false);
    disConnectConv_.notify_all();
}

sptr<IHuksAccessExtBase> ExtensionConnection::GetExtConnectProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    return extConnectProxy;
}

bool ExtensionConnection::IsConnected()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    return isConnected_.load();
}

void ExtensionConnection::AddExtDeathRecipient(const wptr<IRemoteObject>& token)
{
    if (token != nullptr && callerDeathRecipient_ != nullptr) {
        token->RemoveDeathRecipient(callerDeathRecipient_);
    }

    if (callerDeathRecipient_ == nullptr) {
        callerDeathRecipient_ = new (std::nothrow) ExtensionDeathRecipient(std::bind(&ExtensionConnection::OnRemoteDied,
            this, std::placeholders::_1));
    }

    if (token != nullptr) {
        token->AddDeathRecipient(callerDeathRecipient_);
    }
}

void ExtensionConnection::RemoveExtDeathRecipient(const wptr<IRemoteObject>& token)
{
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
    if (extConnectProxy) {
        extConnectProxy = nullptr;
    }

    isDeathRemoted = true;
    if (callBackPlugin) {
        callBackPlugin(m_processInfo);
    }
}

void ExtensionConnection::callBackFromPlugin(std::function<void(HksProcessInfo)> callback)
{
    callBackPlugin = callback;
}

ExtensionConnection::ExtensionConnection(const HksProcessInfo &info) : m_processInfo(info)
{
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

