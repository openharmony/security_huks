/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hksgetsdkversion_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include <vector>

namespace OHOS {
namespace Security {
namespace Hks {
void DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> buf(data, data + size);
    struct HksBlob sdkVersion = { buf.size(), buf.data() };
    [[maybe_unused]] int ret = HksGetSdkVersion(&sdkVersion);
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
