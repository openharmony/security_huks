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

#include "hksimportcertificate_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t resourceIdSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> resourceIdBuf = fdp.ConsumeBytes<uint8_t>(resourceIdSize);
    if (resourceIdBuf.size() == 0) {
        resourceIdBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob resourceId = { static_cast<uint32_t>(resourceIdBuf.size()), resourceIdBuf.data() };

    HksExtCertInfo certInfo = { 0 };
    certInfo.purpose = fdp.ConsumeIntegral<int32_t>();

    uint32_t indexSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> indexBuf = fdp.ConsumeBytes<uint8_t>(indexSize);
    if (indexBuf.size() == 0) {
        indexBuf = std::vector<uint8_t>(1, 0);
    }
    certInfo.index = { static_cast<uint32_t>(indexBuf.size()), indexBuf.data() };

    uint32_t certSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> certBuf = fdp.ConsumeBytes<uint8_t>(certSize);
    if (certBuf.size() == 0) {
        certBuf = std::vector<uint8_t>(1, 0);
    }
    certInfo.cert = { static_cast<uint32_t>(certBuf.size()), certBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksImportCertificate(&resourceId, &certInfo, ps.s);
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