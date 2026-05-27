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

#include "hksanonattestkeyoffline_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    (void)HksFuzzGenerateKey(fdp, keyAlias);

    std::vector<uint8_t> certRootBuffer(4096);
    std::vector<uint8_t> certCaBuffer(4096);
    std::vector<uint8_t> certDeviceBuffer(4096);
    std::vector<uint8_t> certAppBuffer(4096);
    struct HksBlob resultCerts[4] = {
        { static_cast<uint32_t>(certRootBuffer.size()), certRootBuffer.data() },
        { static_cast<uint32_t>(certCaBuffer.size()), certCaBuffer.data() },
        { static_cast<uint32_t>(certDeviceBuffer.size()), certDeviceBuffer.data() },
        { static_cast<uint32_t>(certAppBuffer.size()), certAppBuffer.data() },
    };
    struct HksCertChain certChain = {
        .certs = resultCerts,
        .certsCount = 4
    };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksAnonAttestKeyOffline(&keyAlias, ps.s, &certChain);
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