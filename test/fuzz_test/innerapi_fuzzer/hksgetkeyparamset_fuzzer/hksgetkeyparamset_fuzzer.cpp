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

#include "hksgetkeyparamset_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

constexpr int ALIAS_SIZE = 10;

namespace OHOS {
namespace Security {
namespace Hks {

int DoSomethingInterestingWithMyAPI(uint8_t *data, size_t size)
{
    if (data == nullptr || size < ALIAS_SIZE) {
        return -1;
    }

    struct HksBlob keyAlias = { ALIAS_SIZE, ReadData<uint8_t *>(data, size, ALIAS_SIZE) };
    size_t inSize = size >> 1; // same as size / 2 to avoid magic number
    WrapParamSet psIn = ConstructHksParamSetFromFuzz(data, inSize);
    size = size - ((size >> 1) - inSize);

    WrapParamSet psOut = ConstructHksParamSetFromFuzz(data, size);

    [[maybe_unused]] int ret = HksGetKeyParamSet(&keyAlias, psIn.s, psOut.s);

    return 0;
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    return OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(v.data(), v.size());
}

