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

#ifndef OHOS_SECURITY_HUKS_IEXTENSION_H
#define OHOS_SECURITY_HUKS_IEXTENSION_H

#include <cstdint>
#include <vector>
#include <iremote_broker.h>
#include <string_ex.h>

namespace OHOS {
namespace Security {
namespace Huks {

enum class IExtensionIpcCode {
    COMMAND_TEST = MIN_TRANSACTION_ID,
    COMMAND_ON_CREATE_REMOTE_INDEX,
    COMMAND_ON_GET_REMOTE_HANDLE,
    COMMAND_ON_OPEN_REMOTE_HANDLE,
    COMMAND_ON_CLOSE_REMOTE_HANDLE,
};

class IExtension : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.Huks.IExtension");

    virtual ErrCode test(
        const std::string& testIn,
        std::vector<std::string>& testOut) = 0;

    virtual ErrCode OnCreateRemoteIndex(
        const std::string& abilityName,
        std::string& index) = 0;

    virtual ErrCode OnGetRemoteHandle(
        const std::string& index,
        std::string& handle) = 0;

    virtual ErrCode OnOpenRemoteHandle(
        const std::string& handle) = 0;

    virtual ErrCode OnCloseRemoteHandle(
        const std::string& index) = 0;
protected:
    const int VECTOR_MAX_SIZE = 102400;
    const int LIST_MAX_SIZE = 102400;
    const int SET_MAX_SIZE = 102400;
    const int MAP_MAX_SIZE = 102400;
};
} // namespace Huks
} // namespace Security
} // namespace OHOS
#endif // OHOS_SECURITY_HUKS_IEXTENSION_H

