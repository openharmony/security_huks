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

#ifndef HKS_AMS_CONNECTION_H
#define HKS_AMS_CONNECTION_H
#include "hks_extension_connection.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace Huks {
int32_t AMSConnectAbility(const AAFwk::Want &want, sptr<ExtensionConnection> &connect, int32_t userid);

void AMSDisconnectAbility(sptr<ExtensionConnection> &connect);

sptr<IHuksAccessExtBase> ChangeIRemoteObjectToIHuksAccessExtBase(const sptr<IRemoteObject>& remoteObject);
}
}
}
#endif