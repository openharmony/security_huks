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

#include "hksmac_fuzzer.h"

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

    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> srcBuf = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcBuf.size() == 0) {
        srcBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob srcData = { static_cast<uint32_t>(srcBuf.size()), srcBuf.data() };

    std::vector<uint8_t> macBuf(64);
    struct HksBlob mac = { static_cast<uint32_t>(macBuf.size()), macBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksMac(&keyAlias, ps.s, &srcData, &mac);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob hmacAlias = { 14, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_mac_hmac")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    int32_t ret = HksGenerateKey(&hmacAlias, genPs.s, nullptr);
    printf("fuzz_mac init: GenerateKey ret=%d\n", ret);

    uint8_t srcBuf[] = { 't', 'e', 's', 't' };
    struct HksBlob srcData = { 4, srcBuf };
    uint8_t macBuf[64] = {0};
    struct HksBlob macData = { 64, macBuf };
    WrapParamSet macPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    ret = HksMac(&hmacAlias, macPs.s, &srcData, &macData);
    printf("fuzz_mac init: HksMac ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}