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

#include "hksgetremoteproperty_fuzzer.h"

#include "hks_fuzz_util.h"
#include "hks_type_enum.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    enum HksExtPropertyOperation operation =
        static_cast<enum HksExtPropertyOperation>(fdp.ConsumeIntegralInRange<int32_t>(0, 1));

    uint32_t idSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resIdBuf = fdp.ConsumeBytes<uint8_t>(idSize);
    if (resIdBuf.size() == 0) {
        resIdBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resIdBuf.size()), resIdBuf.data() };

    uint32_t propIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> propIdBuf = fdp.ConsumeBytes<uint8_t>(propIdSize);
    if (propIdBuf.size() == 0) {
        propIdBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob propertyId = { static_cast<uint32_t>(propIdBuf.size()), propIdBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    HksParamSet *psOut = nullptr;
    return HksSetOrGetRemoteProperty(operation, &resourceId, &propertyId, ps.s, &psOut);
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