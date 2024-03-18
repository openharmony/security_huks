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

#include "hksimportwrappedkey_fuzzer.h"

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
    if (data == nullptr || size < (ALIAS_SIZE + ALIAS_SIZE + sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob keyAlias = { ALIAS_SIZE, ReadData<uint8_t *>(data, size, ALIAS_SIZE) };
    struct HksBlob wrappingKeyAlias = { ALIAS_SIZE, ReadData<uint8_t *>(data, size, ALIAS_SIZE) };
    uint32_t wrappedKeySize = *ReadData<uint32_t *>(data, size, sizeof(uint32_t));
    if (size < wrappedKeySize) {
        return -1;
    }
    struct HksBlob wrappedKeyData = { wrappedKeySize, ReadData<uint8_t *>(data, size, wrappedKeySize) };
    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);

    [[maybe_unused]] int ret = HksImportWrappedKey(&keyAlias, &wrappingKeyAlias, ps.s, &wrappedKeyData);

    return 0;
}
}}}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    return OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(v.data(), v.size());
}

