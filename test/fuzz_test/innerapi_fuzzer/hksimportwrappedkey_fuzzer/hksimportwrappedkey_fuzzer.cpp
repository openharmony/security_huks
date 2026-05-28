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

#include "hksimportwrappedkey_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> keyAliasBuf = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (keyAliasBuf.size() == 0) {
        keyAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasBuf.size()), keyAliasBuf.data() };

    uint32_t wrappingAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> wrappingAliasBuf = fdp.ConsumeBytes<uint8_t>(wrappingAliasSize);
    if (wrappingAliasBuf.size() == 0) {
        wrappingAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob wrappingKeyAlias = { static_cast<uint32_t>(wrappingAliasBuf.size()), wrappingAliasBuf.data() };

    (void)HksFuzzGenerateKey(fdp, wrappingKeyAlias);

    uint32_t wrappedKeySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> wrappedKeyBuf = fdp.ConsumeBytes<uint8_t>(wrappedKeySize);
    if (wrappedKeyBuf.size() == 0) {
        wrappedKeyBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob wrappedKeyData = { static_cast<uint32_t>(wrappedKeyBuf.size()), wrappedKeyBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksImportWrappedKey(&keyAlias, &wrappingKeyAlias, ps.s, &wrappedKeyData);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob wrapAlias = { 20, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_wrapkey_wrapping")) };
    struct HksBlob targetAlias = { 18, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_wrapkey_target")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 } });
    int32_t ret = HksGenerateKey(&wrapAlias, genPs.s, nullptr);
    printf("fuzz_importwrappedkey init: GenerateKey(wrapping) ret=%d\n", ret);

    uint8_t wrappedBuf[512] = {0};
    struct HksBlob wrappedData = { 512, wrappedBuf };
    WrapParamSet importPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP } });
    ret = HksImportWrappedKey(&targetAlias, &wrapAlias, importPs.s, &wrappedData);
    printf("fuzz_importwrappedkey init: HksImportWrappedKey ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}