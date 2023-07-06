/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_service_on_remote_request_fuzzer.h"

#include <securec.h>

#include "hks_client_service.h"
#include "hks_sa.h"
#include "huks_service_ipc_interface_code.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        // Initialize the huks service
        HksServiceInitialize();
        const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.hks.service";
        sptr<OHOS::Security::Hks::HksService> ptrInstance = OHOS::Security::Hks::HksService::GetInstance();

        // use loop to call each service function
        for (uint32_t msgcode = HKS_MSG_BASE; msgcode < HKS_MSG_MAX; msgcode++) {
            // init parcel
            MessageParcel dataParcel;
            MessageParcel replyParcel;
            MessageOption optionSync = MessageOption::TF_SYNC;
            MessageOption optionAsync = MessageOption::TF_ASYNC;

            // Sync
            dataParcel.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
            dataParcel.WriteUint32(0); // outData
            dataParcel.WriteUint32(static_cast<uint32_t>(size)); // inData
            dataParcel.WriteBuffer(data, size);
            (void)ptrInstance->OnRemoteRequest(msgcode, dataParcel, replyParcel, optionSync);

            // Async
            dataParcel.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
            dataParcel.WriteUint32(0); // outData
            dataParcel.WriteUint32(static_cast<uint32_t>(size)); // inData
            dataParcel.WriteBuffer(data, size);
            (void)ptrInstance->OnRemoteRequest(msgcode, dataParcel, replyParcel, optionAsync);
        }
        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
