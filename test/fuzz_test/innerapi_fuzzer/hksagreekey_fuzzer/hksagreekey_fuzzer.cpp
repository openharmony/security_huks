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
#include "hksagreekey_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t privSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> priv = fdp.ConsumeBytes<uint8_t>(privSize);
    if (priv.size() == 0) {
        priv = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob privateKey = { static_cast<uint32_t>(priv.size()), priv.data() };

    uint32_t pubSize = fdp.ConsumeIntegralInRange<uint32_t>(8, 512);
    std::vector<uint8_t> pub = fdp.ConsumeBytes<uint8_t>(pubSize);
    if (pub.size() == 0) {
        pub = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob peerPublicKey = { static_cast<uint32_t>(pub.size()), pub.data() };

    uint32_t agreedSize = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    std::vector<uint8_t> agreedBuf(agreedSize);
    struct HksBlob agreedKey = { static_cast<uint32_t>(agreedBuf.size()), agreedBuf.data() };

    (void)HksFuzzGenerateKey(fdp, privateKey);

    return HksAgreeKey(ps.s, &privateKey, &peerPublicKey, &agreedKey);
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