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
#include "hksexportchipsetplatformpublickey_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

constexpr int SALT_SIZE = 32;
constexpr int PUB_KEY_SIZE = 1024;

namespace OHOS {
namespace Security {
namespace Hks {

int DoSomethingInterestingWithMyAPI(uint8_t *data, size_t size)
{
    if (data == nullptr || size <= SALT_SIZE) {
        return -1;
    }

    struct HksBlob salt = { SALT_SIZE, ReadData<uint8_t *>(data, size, SALT_SIZE) };
    std::vector<uint8_t> pubKeyBuffer(PUB_KEY_SIZE);
    struct HksBlob pubKey = { pubKeyBuffer.size(), pubKeyBuffer.data() };

    [[maybe_unused]] int ret =
        HksExportChipsetPlatformPublicKey(&salt, HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, &pubKey);
    return 0;
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> v(data, data + size);
    return OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(v.data(), v.size());
}

