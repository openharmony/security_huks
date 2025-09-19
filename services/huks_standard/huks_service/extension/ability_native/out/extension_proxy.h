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

#ifndef OHOS_SECURITY_HUKS_EXTENSIONPROXY_H
#define OHOS_SECURITY_HUKS_EXTENSIONPROXY_H

#include <iremote_proxy.h>
#include "iextension.h"

namespace OHOS {
namespace Security {
namespace Huks {

class ExtensionProxy : public IRemoteProxy<IExtension> {
public:
    explicit ExtensionProxy(
        const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IExtension>(remote)
    {}

    virtual ~ExtensionProxy()
    {}

    ErrCode test(
        const std::string& testIn,
        std::vector<std::string>& testOut) override;

    ErrCode OnCreateRemoteIndex(
        const std::string& abilityName,
        std::string& index) override;

    ErrCode OnGetRemoteHandle(
        const std::string& index,
        std::string& handle) override;

    ErrCode OnOpenRemoteHandle(
        const std::string& handle) override;

    ErrCode OnCloseRemoteHandle(
        const std::string& index) override;

private:
    static inline BrokerDelegator<ExtensionProxy> delegator_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // OHOS_SECURITY_HUKS_EXTENSIONPROXY_H

