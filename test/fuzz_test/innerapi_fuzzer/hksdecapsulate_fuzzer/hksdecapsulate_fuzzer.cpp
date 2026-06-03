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
#include "hksdecapsulate_fuzzer.h"

#include "hks_fuzz_util.h"
#include "hks_mem.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace Hks {

static constexpr uint32_t ML_KEM_CIPHERTEXT_SIZE_768 = 1088;
static constexpr uint32_t ML_KEM_CIPHERTEXT_SIZE_1024 = 1568;

static uint8_t encapResultBuf768[ML_KEM_CIPHERTEXT_SIZE_768 + 32];
static uint8_t encapResultBuf1024[ML_KEM_CIPHERTEXT_SIZE_1024 + 32];

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp) {
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t keyAliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> keyAliasData = fdp.ConsumeBytes<uint8_t>(keyAliasSize);
    if (keyAliasData.size() == 0) {
        keyAliasData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(keyAliasData.size()), keyAliasData.data() };

    uint32_t ctSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 2048);
    std::vector<uint8_t> ctData = fdp.ConsumeBytes<uint8_t>(ctSize);
    if (ctData.size() == 0) {
        ctData = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob ciphertext = { static_cast<uint32_t>(ctData.size()), ctData.data() };

    return HksDecapsulate(&keyAlias, ps.s, NULL, NULL, &ciphertext);
}

static int32_t InitEncapResult(struct HksBlob *alias, WrapParamSet &encapPs, uint8_t *buf) {
    struct HksEncapsulationResult encapResult = { { 0, NULL }, { 0, NULL } };
    int32_t ret = HksEncapsulate(alias, encapPs.s, NULL, NULL, &encapResult);
    if (ret == HKS_SUCCESS) {
        (void)memcpy_s(buf, encapResult.encapsulatedData.size,
            encapResult.encapsulatedData.data, encapResult.encapsulatedData.size);
    }
    HKS_FREE_ENCAPSULATION_RESULT(&encapResult);
    return ret;
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob alias768 = { 21, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_decap_ml_kem768")) };
    struct HksBlob alias1024 = { 23, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_decap_ml_kem1024")) };
    WrapParamSet genPs768 = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP } });
    WrapParamSet genPs1024 = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_UNWRAP } });
    int32_t ret = HksGenerateKey(&alias768, genPs768.s, nullptr);
    printf("fuzz_decapsulate init: GenerateKey768 ret=%d\n", ret);
    ret = HksGenerateKey(&alias1024, genPs1024.s, nullptr);
    printf("fuzz_decapsulate init: GenerateKey1024 ret=%d\n", ret);

    WrapParamSet encapPs768 = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_768 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP } });
    ret = OHOS::Security::Hks::InitEncapResult(&alias768, encapPs768, OHOS::Security::Hks::encapResultBuf768);
    printf("fuzz_decapsulate init: Encapsulate768 ret=%d\n", ret);

    WrapParamSet encapPs1024 = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ML_KEM },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ML_KEM_KEY_PARAM_SET_1024 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_WRAP } });
    ret = OHOS::Security::Hks::InitEncapResult(&alias1024, encapPs1024, OHOS::Security::Hks::encapResultBuf1024);
    printf("fuzz_decapsulate init: Encapsulate1024 ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);

    return 0;
}