/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "hks_ability_manager_service_connection.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "hks_template.h"

namespace OHOS {
namespace Security {
namespace Huks {

namespace {
constexpr int32_t EXTENSION_ABILITY_TYPE_SERVICE = 3;
constexpr uint32_t AMS_CONNECT_ABILITY_MSG_CODE = 1034;   // CONNECT_ABILITY_WITH_TYPE
constexpr uint32_t AMS_DISCONNECT_ABILITY_MSG_CODE = 1003; // DISCONNECT_ABILITY
constexpr int32_t ABILITY_MANAGER_SA_ID = ABILITY_MGR_SERVICE_ID; // 180

sptr<IRemoteObject> GetAbilityManagerRemote()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HKS_LOG_E("failed to get SystemAbilityManager");
        return nullptr;
    }
    auto remote = samgr->GetSystemAbility(ABILITY_MANAGER_SA_ID);
    if (remote == nullptr) {
        HKS_LOG_E("failed to get AbilityManager remote object");
        return nullptr;
    }
    return remote;
}
}

int32_t AMSConnectAbility(const AAFwk::Want &want, const sptr<ExtensionConnection> &connect, int32_t userid)
{
    auto remote = GetAbilityManagerRemote();
    HKS_IF_NULL_LOGE_RETURN(remote, HKS_ERROR_REMOTE_OPERATION_FAILED, "get AbilityManager remote failed")

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(u"ohos.aafwk.AbilityManager")) {
        HKS_LOG_E("write interface token failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteParcelable(&want)) {
        HKS_LOG_E("write want failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (connect->AsObject() != nullptr) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(connect->AsObject())) {
            HKS_LOG_E("write connect failed");
            return HKS_ERROR_REMOTE_OPERATION_FAILED;
        }
    } else {
        if (!data.WriteBool(false)) {
            HKS_LOG_E("write connect bool failed");
            return HKS_ERROR_REMOTE_OPERATION_FAILED;
        }
    }
    // no callerToken
    if (!data.WriteBool(false)) {
        HKS_LOG_E("write callerToken bool failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteInt32(userid)) {
        HKS_LOG_E("write userId failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteInt32(EXTENSION_ABILITY_TYPE_SERVICE)) {
        HKS_LOG_E("write extensionType failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteBool(false)) { // isQueryExtensionOnly
        HKS_LOG_E("write isQueryExtensionOnly failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteUint64(0)) { // specifiedFullTokenId
        HKS_LOG_E("write specifiedFullTokenId failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteInt32(0)) { // loadTimeout
        HKS_LOG_E("write loadTimeout failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    if (!data.WriteParcelable(nullptr)) { // indirectCallerInfo
        HKS_LOG_E("write indirectCallerInfo failed");
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }

    int32_t ret = remote->SendRequest(AMS_CONNECT_ABILITY_MSG_CODE, data, reply, option);
    HKS_IF_TRUE_LOGE_RETURN(ret != NO_ERROR, HKS_ERROR_REMOTE_OPERATION_FAILED,
        "SendRequest connect ability failed, ret = %" LOG_PUBLIC "d", ret)
    return reply.ReadInt32();
}

void AMSDisconnectAbility(const sptr<ExtensionConnection> &connect)
{
    auto remote = GetAbilityManagerRemote();
    HKS_IF_NULL_LOGE_RETURN_VOID(remote, "get AbilityManager remote failed")

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(u"ohos.aafwk.AbilityManager")) {
        HKS_LOG_E("write interface token failed");
        return;
    }
    if (!data.WriteRemoteObject(connect->AsObject())) {
        HKS_LOG_E("write connect failed");
        return;
    }

    int32_t ret = remote->SendRequest(AMS_DISCONNECT_ABILITY_MSG_CODE, data, reply, option);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != NO_ERROR,
        "SendRequest disconnect ability failed, ret = %" LOG_PUBLIC "d", ret)
}

}
}
}
