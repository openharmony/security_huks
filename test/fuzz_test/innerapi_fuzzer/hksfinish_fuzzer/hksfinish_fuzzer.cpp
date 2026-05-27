/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "hksfinish_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    std::vector<uint8_t> handleBytes = fdp.ConsumeBytes<uint8_t>(sizeof(uint64_t));
    if (handleBytes.empty()) {
        return 0;
    }
    struct HksBlob handle = { static_cast<uint32_t>(handleBytes.size()), handleBytes.data() };

    uint32_t inDataSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> inBuf = fdp.ConsumeBytes<uint8_t>(inDataSize);
    if (inBuf.size() == 0) {
        inBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob inData = { static_cast<uint32_t>(inBuf.size()), inBuf.data() };

    std::vector<uint8_t> outBuf(inDataSize);
    struct HksBlob outData = { static_cast<uint32_t>(outBuf.size()), outBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksFinish(&handle, ps.s, &inData, &outData);
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