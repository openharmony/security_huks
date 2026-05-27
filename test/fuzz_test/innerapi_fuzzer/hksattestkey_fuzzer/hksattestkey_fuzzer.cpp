/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "hksattestkey_fuzzer.h"

#include <securec.h>
#include <vector>

#include "hks_api.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"

#include "hks_fuzz_util.h"

constexpr int CERT_SIZE = 4096;
constexpr int CERT_COUNT = 4;

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange(1, 32);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    (void)HksFuzzGenerateKey(fdp, keyAlias);

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    std::vector<uint8_t> certRootBuffer(CERT_SIZE);
    std::vector<uint8_t> certCaBuffer(CERT_SIZE);
    std::vector<uint8_t> certDeviceBuffer(CERT_SIZE);
    std::vector<uint8_t> certAppBuffer(CERT_SIZE);
    struct HksBlob resultCerts[CERT_COUNT] = {
        { CERT_SIZE, certRootBuffer.data() },
        { CERT_SIZE, certCaBuffer.data() },
        { CERT_SIZE, certDeviceBuffer.data() },
        { CERT_SIZE, certAppBuffer.data() },
    };
    struct HksCertChain certChain = {
        .certs = resultCerts,
        .certsCount = CERT_COUNT
    };

    return HksAttestKey(&keyAlias, ps.s, &certChain);
}
}}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
