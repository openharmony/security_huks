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
#include "hksencrypt_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> keyVec = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyVec.size() == 0) {
        keyVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob key = { static_cast<uint32_t>(keyVec.size()), keyVec.data() };

    uint32_t ptSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> ptBuf = fdp.ConsumeBytes<uint8_t>(ptSize);
    if (ptBuf.size() == 0) {
        ptBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob plainText = { static_cast<uint32_t>(ptBuf.size()), ptBuf.data() };

    uint32_t ctSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    std::vector<uint8_t> ct(ctSize);
    struct HksBlob cipherText = { static_cast<uint32_t>(ct.size()), ct.data() };

    (void)HksFuzzGenerateKey(fdp, key);

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksEncrypt(&key, ps.s, &plainText, &cipherText);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob aesAlias = { 16, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_encrypt_aes")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    int32_t ret = HksGenerateKey(&aesAlias, genPs.s, nullptr);
    printf("fuzz_encrypt init: GenerateKey ret=%d\n", ret);

    uint8_t srcBuf[] = { 't', 'e', 's', 't' };
    struct HksBlob srcData = { 4, srcBuf };
    uint8_t cipherBuf[512] = {0};
    struct HksBlob cipherText = { 512, cipherBuf };
    WrapParamSet encPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    ret = HksEncrypt(&aesAlias, encPs.s, &srcData, &cipherText);
    printf("fuzz_encrypt init: HksEncrypt ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
