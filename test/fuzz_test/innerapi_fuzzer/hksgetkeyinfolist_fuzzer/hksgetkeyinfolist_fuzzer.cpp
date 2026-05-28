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

#include "hksgetkeyinfolist_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t listCount = fdp.ConsumeIntegralInRange<uint32_t>(1, 10);

    std::vector<struct HksKeyInfo> keyInfoList(listCount);
    std::vector<std::vector<uint8_t>> aliasStorage(listCount);
    for (uint32_t i = 0; i < listCount; i++) {
        uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
        aliasStorage[i] = fdp.ConsumeBytes<uint8_t>(aliasSize);
        if (aliasStorage[i].size() == 0) {
            aliasStorage[i] = std::vector<uint8_t>(1, 0);
        }
        keyInfoList[i].alias = { static_cast<uint32_t>(aliasStorage[i].size()), aliasStorage[i].data() };
    }

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    for (uint32_t i = 0; i < listCount; i++) {
        keyInfoList[i].paramSet = ps.s;
    }

    return HksGetKeyInfoList(ps.s, keyInfoList.data(), &listCount);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob rsaAlias = { 20, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_infolist_rsa")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS } });
    int32_t ret = HksGenerateKey(&rsaAlias, genPs.s, nullptr);
    printf("fuzz_getkeyinfolist init: GenerateKey ret=%d\n", ret);

    uint32_t listCount = 10;
    std::vector<struct HksKeyInfo> keyInfoList(listCount);
    WrapParamSet listPs = BuildFixedParamSet({});
    ret = HksGetKeyInfoList(listPs.s, keyInfoList.data(), &listCount);
    printf("fuzz_getkeyinfolist init: HksGetKeyInfoList ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}