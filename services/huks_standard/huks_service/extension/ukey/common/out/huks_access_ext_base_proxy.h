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

#ifndef OHOS_SECURITY_HUKS_HUKSACCESSEXTBASEPROXY_H
#define OHOS_SECURITY_HUKS_HUKSACCESSEXTBASEPROXY_H

#include <iremote_proxy.h>
#include "ihuks_access_ext_base.h"

namespace OHOS {
namespace Security {
namespace Huks {

class HuksAccessExtBaseProxy : public IRemoteProxy<IHuksAccessExtBase> {
public:
    explicit HuksAccessExtBaseProxy(
        const sptr<IRemoteObject>& remote)
        : IRemoteProxy<IHuksAccessExtBase>(remote)
    {}

    virtual ~HuksAccessExtBaseProxy()
    {}

    ErrCode OpenRemoteHandle(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) override;

private:
    static inline BrokerDelegator<HuksAccessExtBaseProxy> delegator_;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // OHOS_SECURITY_HUKS_HUKSACCESSEXTBASEPROXY_H

