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
#include "hksgeneraterandom_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t randomSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 100);
    std::vector<uint8_t> randomBuf(randomSize);
    struct HksBlob random = { static_cast<uint32_t>(randomBuf.size()), randomBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    return HksGenerateRandom(ps.s, &random);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    uint8_t randomBuf[32] = {0};
    struct HksBlob random = { 32, randomBuf };
    WrapParamSet randomPs = BuildFixedParamSet({});
    int32_t ret = HksGenerateRandom(randomPs.s, &random);
    printf("fuzz_generaterandom init: HksGenerateRandom ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
