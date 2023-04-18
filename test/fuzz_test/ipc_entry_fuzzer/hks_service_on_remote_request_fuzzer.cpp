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

#include "hks_mem.h"
#include "hks_message_code.h"
#include "hks_param.h"
#include "hks_type.h"
#include "iservice_registry.h"

namespace {
constexpr int SA_ID_KEYSTORE_SERVICE = 3510;
const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.hks.service";
}

namespace OHOS {
    static sptr<IRemoteObject> GetHksProxy()
    {
        auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        sptr<IRemoteObject> hksProxy = registry->GetSystemAbility(SA_ID_KEYSTORE_SERVICE);
        return hksProxy;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        // 构造测试用例
        MessageParcel dataParcel;
        MessageParcel replyParcel;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;

        dataParcel.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
        dataParcel.WriteUint32(static_cast<uint32_t>(size));
        dataParcel.WriteBuffer(data, size);
        
        // 调用函数
        sptr<IRemoteObject> hksProxy = GetHksProxy();
        int error;
        for (uint32_t msgcode = HKS_MSG_BASE; msgcode <= HKS_MSG_MAX; msgcode++) {
            error = hksProxy->SendRequest(msgcode, dataParcel, replyParcel, optionSync);
            error = hksProxy->SendRequest(msgcode, dataParcel, replyParcel, optionAsync);
        }

        return true;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
