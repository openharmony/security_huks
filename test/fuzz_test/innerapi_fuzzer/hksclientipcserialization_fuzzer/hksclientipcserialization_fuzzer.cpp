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

#include <securec.h>

#include "hks_client_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
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

// Fuzz HksOnceParamPack: fuzz controls destData size, key blob, paramSet, and index offset
static int32_t FuzzHksOnceParamPack(FuzzedDataProvider &fdp)
{
    uint32_t destSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(uint32_t), MAX_IPC_BUF_SIZE);
    auto destData = fdp.ConsumeBytes<uint8_t>(destSize);
    if (destData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob destBlob = { static_cast<uint32_t>(destData.size()), destData.data() };

    // HksOnceParamPack calls CopyBlobToBuffer(key) — key must be valid
    uint32_t keySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto keyData = fdp.ConsumeBytes<uint8_t>(keySize);
    if (keyData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob keyBlob = { static_cast<uint32_t>(keyData.size()), keyData.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    if (ps.s == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t index = fdp.ConsumeIntegralInRange<uint32_t>(0, destBlob.size);
    return HksOnceParamPack(&destBlob, &keyBlob, ps.s, &index);
}

// Fuzz HksAgreeKeyPack: fuzz controls destData, paramSet, and key blobs
static int32_t FuzzHksAgreeKeyPack(FuzzedDataProvider &fdp)
{
    uint32_t destSize = fdp.ConsumeIntegralInRange<uint32_t>(sizeof(uint32_t), MAX_IPC_BUF_SIZE);
    auto destData = fdp.ConsumeBytes<uint8_t>(destSize);
    if (destData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob destBlob = { static_cast<uint32_t>(destData.size()), destData.data() };

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    if (ps.s == nullptr) {
        return HKS_ERROR_NULL_POINTER;
    }

    // HksAgreeKeyPack calls CopyBlobToBuffer(privateKey/peerPublicKey) and agreedKey->size
    uint32_t privKeySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto privKeyData = fdp.ConsumeBytes<uint8_t>(privKeySize);
    if (privKeyData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob privateKey = { static_cast<uint32_t>(privKeyData.size()), privKeyData.data() };

    uint32_t peerPubKeySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto peerPubKeyData = fdp.ConsumeBytes<uint8_t>(peerPubKeySize);
    if (peerPubKeyData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob peerPublicKey = { static_cast<uint32_t>(peerPubKeyData.size()), peerPubKeyData.data() };

    uint32_t agreedKeySize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto agreedKeyData = fdp.ConsumeBytes<uint8_t>(agreedKeySize);
    if (agreedKeyData.empty()) {
        return HKS_ERROR_INSUFFICIENT_DATA;
    }
    struct HksBlob agreedKey = { static_cast<uint32_t>(agreedKeyData.size()), agreedKeyData.data() };

    return HksAgreeKeyPack(&destBlob, ps.s, &privateKey, &peerPublicKey, &agreedKey);
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
    uint32_t n = 1;
    struct HksKeyInfo *keyInfoList = (struct HksKeyInfo *)HksMalloc(n * sizeof(struct HksKeyInfo));
    if (keyInfoList == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(keyInfoList, n * sizeof(struct HksKeyInfo), 0, n * sizeof(struct HksKeyInfo));
    uint8_t *aliasBuf = (uint8_t *)HksMalloc(MAX_IPC_BUF_SIZE);
    struct HksParamSet *ps = (struct HksParamSet *)HksMalloc(HKS_DEFAULT_PARAM_SET_SIZE);
    if (aliasBuf == nullptr || ps == nullptr) {
        HKS_FREE(aliasBuf);
        HKS_FREE(ps);
        HKS_FREE(keyInfoList);
        return HKS_ERROR_MALLOC_FAIL;
    }
    ps->paramSetSize = HKS_DEFAULT_PARAM_SET_SIZE;
    ps->paramsCnt = 0;
    keyInfoList[0].alias = { MAX_IPC_BUF_SIZE, aliasBuf };
    keyInfoList[0].paramSet = ps;
    int32_t ret = HksGetKeyInfoListUnpackFromService(&srcBlob, &n, keyInfoList);
    HKS_FREE(aliasBuf);
    HKS_FREE(ps);
    HKS_FREE(keyInfoList);
    return ret;
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
    // HksCertificateChainUnpackFromService dereferences certChain->certs[i].data
    // when certsCount from buffer > 0 — must provide valid certs array
    uint32_t certsCount = fdp.ConsumeIntegralInRange<uint32_t>(1, 4);
    std::vector<std::vector<uint8_t>> certBuffers(certsCount, std::vector<uint8_t>(4096, 0));
    std::vector<struct HksBlob> certs(certsCount);
    for (uint32_t i = 0; i < certsCount; i++) {
        certs[i] = { 4096, certBuffers[i].data() };
    }
    struct HksCertChain certChain = { certs.data(), certsCount };
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
