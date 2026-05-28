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

#include "hkswrapkey_fuzzer.h"

#include "hks_fuzz_util.h"

constexpr int WRAPPED_KEY_SIZE = 2048;

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyAliasBuf = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    if (keyAliasBuf.size() == 0) {
        keyAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasBuf.size()), keyAliasBuf.data() };

    (void)HksFuzzGenerateKey(fdp, keyAlias);

    uint32_t targetKeyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> targetKeyAliasBuf = fdp.ConsumeBytes<uint8_t>(targetKeyAliasSize);
    if (targetKeyAliasBuf.size() == 0) {
        targetKeyAliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob targetKeyAlias = { static_cast<uint32_t>(targetKeyAliasBuf.size()), targetKeyAliasBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint8_t wrappedData[WRAPPED_KEY_SIZE] = {0};
    struct HksBlob wrappedDataBlob = { WRAPPED_KEY_SIZE, wrappedData };

    return HksWrapKey(&keyAlias, &targetKeyAlias, ps.s, &wrappedDataBlob);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob wrapAlias = { 17, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_wrap_wrapping")) };
    struct HksBlob targetAlias = { 15, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_wrap_target")) };
    WrapParamSet wrapGenPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP | HKS_KEY_PURPOSE_UNWRAP },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 } });
    int32_t ret = HksGenerateKey(&wrapAlias, wrapGenPs.s, nullptr);
    printf("fuzz_wrapkey init: GenerateKey(wrapping) ret=%d\n", ret);

    WrapParamSet targetGenPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 } });
    ret = HksGenerateKey(&targetAlias, targetGenPs.s, nullptr);
    printf("fuzz_wrapkey init: GenerateKey(target) ret=%d\n", ret);

    uint8_t wrappedBuf[512] = {0};
    struct HksBlob wrappedData = { 512, wrappedBuf };
    WrapParamSet wrapPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS1_V1_5 } });
    ret = HksWrapKey(&wrapAlias, &targetAlias, wrapPs.s, &wrappedData);
    printf("fuzz_wrapkey init: HksWrapKey ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}