/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

constexpr int WRAPPED_KEY_SIZE = 2048;
constexpr int BLOB_NUM = 3;

namespace OHOS {
namespace Security {
namespace Hks {

int DoSomethingInterestingWithMyAPI(uint8_t *data, size_t size)
{
    if (data == nullptr || size < (BLOB_NUM * sizeof(uint32_t))) {
        return -1;
    }

    struct HksBlob key = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    struct HksBlob srcData = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };
    struct HksBlob mac = { sizeof(uint32_t), ReadData<uint8_t *>(data, size, sizeof(uint32_t)) };

    WrapParamSet ps = ConstructHksParamSetFromFuzz(data, size);

    uint8_t WrappedData[WRAPPED_KEY_SIZE] = {0};
    struct HksBlob wrappedKey = {WRAPPED_KEY_SIZE, WrappedData};
    (void)HksWrapKey(&key, nullptr, ps.s, &wrappedKey);

    (void)HksUnwrapKey(&key, nullptr, &srcData, ps.s);

    (void)HcmIsDeviceKeyExist(ps.s);

    [[maybe_unused]] int ret = HksMac(&key, ps.s, &srcData, &mac);

    return 0;
}

}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(v.data(), v.size());

    return 0;
}
