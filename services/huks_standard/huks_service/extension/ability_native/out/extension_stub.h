/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_SECURITY_HUKS_EXTENSIONSTUB_H
#define OHOS_SECURITY_HUKS_EXTENSIONSTUB_H

#include <iremote_stub.h>
#include "iextension.h"

namespace OHOS {
namespace Security {
namespace Huks {

class ExtensionStub : public IRemoteStub<IExtension> {
public:
    ExtensionStub(bool serialInvokeFlag = false): IRemoteStub(serialInvokeFlag){};
    int32_t OnRemoteRequest(
        uint32_t code,
        MessageParcel& data,
        MessageParcel& reply,
        MessageOption& option) override;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // OHOS_SECURITY_HUKS_EXTENSIONSTUB_H

