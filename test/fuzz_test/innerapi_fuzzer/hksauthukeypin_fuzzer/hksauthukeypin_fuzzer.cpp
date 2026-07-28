/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "hksauthukeypin_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t idSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> idBuf = fdp.ConsumeBytes<uint8_t>(idSize);
    if (idBuf.size() == 0) {
        idBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(idBuf.size()), idBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t retryCount = 0;
    return HksAuthUkeyPin(&resourceId, ps.s, &retryCount);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob resourceId = { 8, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_res")) };
    WrapParamSet authPs = BuildFixedParamSet({});
    uint32_t retryCount = 0;
    int32_t ret = HksAuthUkeyPin(&resourceId, authPs.s, &retryCount);
    printf("fuzz_authukeypin init: HksAuthUkeyPin ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}