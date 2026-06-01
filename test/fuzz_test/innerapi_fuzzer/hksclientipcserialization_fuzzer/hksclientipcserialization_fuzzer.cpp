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

#include "hksclientipcserialization_fuzzer.h"

#include <vector>

#include "hks_client_ipc_serialization.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include "hks_fuzz_util.h"

namespace OHOS {
namespace Security {
namespace Hks {

// Fuzz CopyUint32ToBuffer: fuzz controls destBlob size/content, value, and index offset
static int32_t FuzzCopyUint32ToBuffer(FuzzedDataProvider &fdp)
{
    uint32_t destSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(uint32_t), MAX_IPC_BUF_SIZE);
    auto destData = fdp.ConsumeBytes<uint8_t>(destSize);
    if (destData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob destBlob = { static_cast<uint32_t>(destData.size()), destData.data() };
    uint32_t value = fdp.ConsumeIntegral<uint32_t>();
    uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, destBlob.size);
    return CopyUint32ToBuffer(value, &destBlob, &index);
}

// Fuzz HksOnceParamPack: fuzz controls destData size, optional key/paramSet, and index offset
static int32_t FuzzHksOnceParamPack(FuzzedDataProvider &fdp)
{
    uint32_t destSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(uint32_t), MAX_IPC_BUF_SIZE);
    auto destData = fdp.ConsumeBytes<uint8_t>(destSize);
    if (destData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob destBlob = { static_cast<uint32_t>(destData.size()), destData.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, destBlob.size);
    return HksOnceParamPack(&destBlob, nullptr, ps.s, &index);
}

// Fuzz HksAgreeKeyPack: fuzz controls destData, paramSet, optional blobs
static int32_t FuzzHksAgreeKeyPack(FuzzedDataProvider &fdp)
{
    uint32_t destSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(uint32_t), MAX_IPC_BUF_SIZE);
    auto destData = fdp.ConsumeBytes<uint8_t>(destSize);
    if (destData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob destBlob = { static_cast<uint32_t>(destData.size()), destData.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    return HksAgreeKeyPack(&destBlob, ps.s, nullptr, nullptr, nullptr);
}

// Fuzz HksGetKeyInfoListUnpackFromService: fuzz controls srcData content
static int32_t FuzzHksGetKeyInfoListUnpackFromService(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };
    return HksGetKeyInfoListUnpackFromService(&srcBlob, nullptr, nullptr);
}

// Fuzz HksCertificateChainUnpackFromService: fuzz controls srcData, needEncode, certsCount
static int32_t FuzzHksCertificateChainUnpackFromService(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };
    bool isDeviceCert = fdp.ConsumeBool();
    struct HksCertChain certChain = { .certsCount = fdp.ConsumeIntegralInRange<uint32_t>(0, 8) };
    return HksCertificateChainUnpackFromService(&srcBlob, isDeviceCert, &certChain);
}

// Fuzz EncodeCertChain: fuzz controls inBlob size/content and outBlob size
static int32_t FuzzEncodeCertChain(FuzzedDataProvider &fdp)
{
    uint32_t inSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 4096);
    auto inData = fdp.ConsumeBytes<uint8_t>(inSize);
    if (inData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob inBlob = { static_cast<uint32_t>(inData.size()), inData.data() };

    // Normal path: valid outBlob
    uint32_t outSize = 4096;
    std::vector<uint8_t> outData(outSize, 0);
    struct HksBlob outBlob = { outSize, outData.data() };
    int32_t ret = EncodeCertChain(&inBlob, &outBlob);

    // Edge case: oversized inBlob.size triggers CheckAndCalculateSize early return
    // Only test the size validation path — data pointer is null since it won't be accessed
    struct HksBlob edgeBlob = { .size = fdp.ConsumeIntegralInRange<uint32_t>(UINT32_MAX - 2, UINT32_MAX),
                                .data = nullptr };
    (void)EncodeCertChain(&edgeBlob, nullptr);

    return ret;
}

// Fuzz HksListAliasesUnpackFromService: fuzz controls srcData (including nullptr/empty path)
static int32_t FuzzHksListAliasesUnpackFromService(FuzzedDataProvider &fdp)
{
    bool useEmpty = fdp.ConsumeBool();
    if (useEmpty) {
        struct HksBlob srcBlob = { 0, nullptr };
        return HksListAliasesUnpackFromService(&srcBlob, nullptr);
    }

    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) {
        struct HksBlob srcBlob = { 0, nullptr };
        return HksListAliasesUnpackFromService(&srcBlob, nullptr);
    }
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };
    return HksListAliasesUnpackFromService(&srcBlob, nullptr);
}

using FuzzFunc = int32_t (*)(FuzzedDataProvider &);

static const FuzzFunc fuzzFuncs[] = {
    FuzzCopyUint32ToBuffer,
    FuzzHksOnceParamPack,
    FuzzHksAgreeKeyPack,
    FuzzHksGetKeyInfoListUnpackFromService,
    FuzzHksCertificateChainUnpackFromService,
    FuzzEncodeCertChain,
    FuzzHksListAliasesUnpackFromService,
};

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    auto func = fdp.PickValueInArray(fuzzFuncs);
    return func(fdp);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
