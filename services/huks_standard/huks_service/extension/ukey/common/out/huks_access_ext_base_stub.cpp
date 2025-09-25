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

#include "huks_access_ext_base_stub.h"

namespace OHOS {
namespace Security {
namespace Huks {

int32_t HuksAccessExtBaseStub::OnRemoteRequest(
    uint32_t code,
    MessageParcel& data,
    MessageParcel& reply,
    MessageOption& option)
{
    std::u16string localDescriptor = GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (localDescriptor != remoteDescriptor) {
        return ERR_TRANSACTION_FAILED;
    }
    switch (static_cast<IHuksAccessExtBaseIpcCode>(code)) {
        case IHuksAccessExtBaseIpcCode::COMMAND_OPEN_REMOTE_HANDLE: {
            std::string index = Str16ToStr8(data.ReadString16());
            std::unique_ptr<CppParamSet> params(data.ReadParcelable<CppParamSet>());
            if (!params) {
                return ERR_INVALID_DATA;
            }

            std::string handle;
            int32_t errcode;
            ErrCode errCode = OpenRemoteHandle(index, *params, handle, errcode);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            if (SUCCEEDED(errCode)) {
                if (!reply.WriteString16(Str8ToStr16(handle))) {
                    return ERR_INVALID_DATA;
                }
                if (!reply.WriteInt32(errcode)) {
                    return ERR_INVALID_DATA;
                }
            }
            return ERR_NONE;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_TRANSACTION_FAILED;
}
} // namespace Huks
} // namespace Security
} // namespace OHOS
