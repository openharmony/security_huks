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

#include "huks_access_ext_base_proxy.h"

namespace OHOS {
namespace Security {
namespace Huks {

ErrCode HuksAccessExtBaseProxy::OpenRemoteHandle(
    const std::string& index,
    const CppParamSet& params,
    std::string& handle,
    int32_t& errcode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return ERR_INVALID_VALUE;
    }

    if (!data.WriteString16(Str8ToStr16(index))) {
        return ERR_INVALID_DATA;
    }
    if (!data.WriteParcelable(&params)) {
        return ERR_INVALID_DATA;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        return ERR_INVALID_DATA;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IHuksAccessExtBaseIpcCode::COMMAND_OPEN_REMOTE_HANDLE), data, reply, option);
    if (FAILED(result)) {
        return result;
    }

    ErrCode errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        return errCode;
    }

    handle = Str16ToStr8(reply.ReadString16());
    errcode = reply.ReadInt32();
    return ERR_OK;
}
} // namespace Huks
} // namespace Security
} // namespace OHOS
