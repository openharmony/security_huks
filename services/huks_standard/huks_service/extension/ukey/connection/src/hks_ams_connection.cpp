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

#include "hks_ams_connection.h"
#include "ability_manager_client.h"

namespace OHOS {
namespace Security {
namespace Huks {
int32_t AMSConnectAbility(const AAFwk::Want &want, sptr<ExtensionConnection> &connect, int32_t userid)
{
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, connect, userid);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_REMOTE_OPERATION_FAILED,
        "fail to connect ability by ability manager service. ext error = %" LOG_PUBLIC "d", ret)
    return HKS_SUCCESS;
}

void AMSDisconnectAbility(sptr<ExtensionConnection> &connect)
{
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(connect);
    HKS_IF_TRUE_LOGE_RETURN_VOID(ret != HKS_SUCCESS, "disconnect ability by AMS fail, ret = %{public}d", ret)
    return;
}

sptr<IHuksAccessExtBase> ChangeIRemoteObjectToIHuksAccessExtBase(const sptr<IRemoteObject>& remoteObject)
{
    return iface_cast<HuksAccessExtBaseProxy>(remoteObject);
}

}
}
}