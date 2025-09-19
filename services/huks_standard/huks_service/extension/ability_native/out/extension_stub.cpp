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

#include "extension_stub.h"

namespace OHOS {
namespace Security {
namespace Huks {

int32_t ExtensionStub::OnRemoteRequest(
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
    switch (static_cast<IExtensionIpcCode>(code)) {
        case IExtensionIpcCode::COMMAND_TEST: {
            std::string testIn = Str16ToStr8(data.ReadString16());
            std::vector<std::string> testOut;
            ErrCode errCode = test(testIn, testOut);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            if (SUCCEEDED(errCode)) {
                if (testOut.size() > static_cast<size_t>(VECTOR_MAX_SIZE)) {
                    return ERR_INVALID_DATA;
                }
                reply.WriteInt32(testOut.size());
                for (auto it1 = testOut.begin(); it1 != testOut.end(); ++it1) {
                    if (!reply.WriteString16(Str8ToStr16((*it1)))) {
                        return ERR_INVALID_DATA;
                    }
                }
            }
            return ERR_NONE;
        }
        case IExtensionIpcCode::COMMAND_ON_CREATE_REMOTE_INDEX: {
            std::string abilityName = Str16ToStr8(data.ReadString16());
            std::string index;
            ErrCode errCode = OnCreateRemoteIndex(abilityName, index);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            if (SUCCEEDED(errCode)) {
                if (!reply.WriteString16(Str8ToStr16(index))) {
                    return ERR_INVALID_DATA;
                }
            }
            return ERR_NONE;
        }
        case IExtensionIpcCode::COMMAND_ON_GET_REMOTE_HANDLE: {
            std::string index = Str16ToStr8(data.ReadString16());
            std::string handle;
            ErrCode errCode = OnGetRemoteHandle(index, handle);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            if (SUCCEEDED(errCode)) {
                if (!reply.WriteString16(Str8ToStr16(handle))) {
                    return ERR_INVALID_DATA;
                }
            }
            return ERR_NONE;
        }
        case IExtensionIpcCode::COMMAND_ON_OPEN_REMOTE_HANDLE: {
            std::string handle = Str16ToStr8(data.ReadString16());
            ErrCode errCode = OnOpenRemoteHandle(handle);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
            }
            return ERR_NONE;
        }
        case IExtensionIpcCode::COMMAND_ON_CLOSE_REMOTE_HANDLE: {
            std::string index = Str16ToStr8(data.ReadString16());
            ErrCode errCode = OnCloseRemoteHandle(index);
            if (!reply.WriteInt32(errCode)) {
                return ERR_INVALID_VALUE;
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
