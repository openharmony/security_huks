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
#include "hksbnexpmod_fuzzer.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t xSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> xBuf(xSize);
    struct HksBlob x = { static_cast<uint32_t>(xBuf.size()), xBuf.data() };

    uint32_t aSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> aVec = fdp.ConsumeBytes<uint8_t>(aSize);
    if (aVec.size() == 0) {
        aVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob a = { static_cast<uint32_t>(aVec.size()), aVec.data() };

    uint32_t eSize = fdp.ConsumeIntegralInRange<uint32_t>(4, 64);
    std::vector<uint8_t> eVec = fdp.ConsumeBytes<uint8_t>(eSize);
    if (eVec.size() == 0) {
        eVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob e = { static_cast<uint32_t>(eVec.size()), eVec.data() };

    uint32_t nSize = fdp.ConsumeIntegralInRange<uint32_t>(32, 512);
    std::vector<uint8_t> nVec = fdp.ConsumeBytes<uint8_t>(nSize);
    if (nVec.size() == 0) {
        nVec = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob n = { static_cast<uint32_t>(nVec.size()), nVec.data() };

    return HksBnExpMod(&x, &a, &e, &n);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    uint8_t nBuf[64] = {0};
    uint8_t aBuf[64] = {0};
    uint8_t eBuf[4] = {1, 0, 0, 0};
    uint8_t xBuf[64] = {0};
    struct HksBlob n = { 64, nBuf };
    struct HksBlob a = { 64, aBuf };
    struct HksBlob e = { 4, eBuf };
    struct HksBlob x = { 64, xBuf };
    n.data[63] = 3;
    a.data[0] = 2;
    int32_t ret = HksBnExpMod(&x, &a, &e, &n);
    printf("fuzz_bnexpmod init: HksBnExpMod ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
