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
#include "hksagreekey_fuzzer.h"

#include <securec.h>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t privSize = fdp.ConsumeIntegralInRange(1, 32);
    std::vector<uint8_t> priv = fdp.ConsumeBytes<uint8_t>(privSize);
    struct HksBlob privateKey = { static_cast<uint32_t>(priv.size()), priv.data() };

    uint32_t pubSize = fdp.ConsumeIntegralInRange(8, 512);
    std::vector<uint8_t> pub = fdp.ConsumeBytes<uint8_t>(pubSize);
    struct HksBlob peerPublicKey = { static_cast<uint32_t>(pub.size()), pub.data() };

    uint32_t agreedSize = fdp.ConsumeIntegralInRange(16, 256);
    std::vector<uint8_t> agreedBuf(agreedSize);
    struct HksBlob agreedKey = { static_cast<uint32_t>(agreedBuf.size()), agreedBuf.data() };

    (void)HksFuzzGenerateKey(fdp, privateKey);

    return HksAgreeKey(ps.s, &privateKey, &peerPublicKey, &agreedKey);
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);

    return 0;
}