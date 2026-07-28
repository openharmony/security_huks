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

#include "hksfinish_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    std::vector<uint8_t> handleBytes = fdp.ConsumeBytes<uint8_t>(sizeof(uint64_t));
    if (handleBytes.empty()) {
        return 0;
    }
    struct HksBlob handle = { static_cast<uint32_t>(handleBytes.size()), handleBytes.data() };

    uint32_t inDataSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    std::vector<uint8_t> inBuf = fdp.ConsumeBytes<uint8_t>(inDataSize);
    if (inBuf.size() == 0) {
        inBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob inData = { static_cast<uint32_t>(inBuf.size()), inBuf.data() };

    std::vector<uint8_t> outBuf(inDataSize);
    struct HksBlob outData = { static_cast<uint32_t>(outBuf.size()), outBuf.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    return HksFinish(&handle, ps.s, &inData, &outData);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob aesAlias = { 15, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_finish_aes")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    int32_t ret = HksGenerateKey(&aesAlias, genPs.s, nullptr);
    printf("fuzz_finish init: GenerateKey ret=%d\n", ret);

    uint8_t handleBuf[8] = {0};
    struct HksBlob handle = { 8, handleBuf };
    uint8_t tokenBuf[1024] = {0};
    struct HksBlob token = { 1024, tokenBuf };
    WrapParamSet initPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PKCS7 },
        { .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true } });
    ret = HksInit(&aesAlias, initPs.s, &handle, &token);
    printf("fuzz_finish init: HksInit ret=%d\n", ret);

    uint8_t srcBuf[] = { 't', 'e', 's', 't' };
    struct HksBlob srcData = { 4, srcBuf };
    uint8_t outBuf[512] = {0};
    struct HksBlob outData = { 512, outBuf };
    WrapParamSet updatePs = BuildFixedParamSet({});
    ret = HksUpdate(&handle, updatePs.s, &srcData, &outData);
    printf("fuzz_finish init: HksUpdate ret=%d\n", ret);

    uint8_t finishOutBuf[512] = {0};
    struct HksBlob finishOutData = { 512, finishOutBuf };
    WrapParamSet finishPs = BuildFixedParamSet({});
    ret = HksFinish(&handle, finishPs.s, &srcData, &finishOutData);
    printf("fuzz_finish init: HksFinish ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}