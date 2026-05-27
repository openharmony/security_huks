/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "hksrename_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t oldAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> oldAliasBuf = fdp.ConsumeBytes<uint8_t>(oldAliasSize);
    if (oldAliasBuf.size() == 0) {
        oldAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob oldKeyAlias = { static_cast<uint32_t>(oldAliasBuf.size()), oldAliasBuf.data() };

    (void)HksFuzzGenerateKey(fdp, oldKeyAlias);

    uint32_t newAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> newAliasBuf = fdp.ConsumeBytes<uint8_t>(newAliasSize);
    if (newAliasBuf.size() == 0) {
        newAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob newKeyAlias = { static_cast<uint32_t>(newAliasBuf.size()), newAliasBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksRenameKeyAlias(&oldKeyAlias, ps.s, &newKeyAlias);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    return OHOS::Security::Hks::HksFuzzInitWithGoldenPath();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}