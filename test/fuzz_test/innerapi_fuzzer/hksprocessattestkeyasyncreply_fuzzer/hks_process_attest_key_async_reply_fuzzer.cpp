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

#include "hks_process_attest_key_async_reply_fuzzer.h"

#include "hks_sa_interface.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.hks.service";
        sptr<Security::Hks::HksStub> hksCallback = new (std::nothrow) Security::Hks::HksStub();

        // init parcel
        MessageParcel dataParcel;
        MessageParcel replyParcel;
        MessageOption optionAsync = MessageOption::TF_ASYNC;

        dataParcel.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
        dataParcel.WriteUint32(0); // outData
        dataParcel.WriteUint32(static_cast<uint32_t>(size)); // inData
        dataParcel.WriteBuffer(data, size);
        (void)hksCallback->OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, dataParcel, replyParcel, optionAsync);
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
