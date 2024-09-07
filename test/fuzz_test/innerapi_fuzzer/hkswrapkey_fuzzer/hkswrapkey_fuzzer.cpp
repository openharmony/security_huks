/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hkswrapkey_fuzzer.h"

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include <securec.h>

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

static void HksWrapKeyTest()
{
    HKS_LOG_I("enter HksWrapKeyTest");
    (void)HksWrapKey(nullptr, nullptr, nullptr, nullptr);
}

static void HksUnwrapKeyTest()
{
    HKS_LOG_I("enter HksUnwrapKeyTest");
    (void)HksUnwrapKey(nullptr, nullptr, nullptr, nullptr);
}

static void HcmIsDeviceKeyExistTest()
{
    HKS_LOG_I("enter HcmIsDeviceKeyExistTest");
    (void)HcmIsDeviceKeyExist(nullptr);
}
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    OHOS::Security::Hks::HksWrapKeyTest();
    OHOS::Security::Hks::HksUnwrapKeyTest();
    OHOS::Security::Hks::HcmIsDeviceKeyExistTest();

    return 0;
}
