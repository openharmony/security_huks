/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hksserviceipcserialization_fuzzer.h"

#include <vector>

#include <securec.h>

#include "hks_service_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include "hks_fuzz_util.h"
#define MAX_IPC_BUF_SIZE 0x10000

namespace OHOS {
namespace Security {
namespace Hks {

static int32_t FuzzHksRenameKeyAliasUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob oldKeyAlias = { 0, nullptr };
    struct HksBlob newKeyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksRenameKeyAliasUnpack(&srcBlob, &oldKeyAlias, &newKeyAlias, &paramSet);
    HKS_FREE(oldKeyAlias.data);
    HKS_FREE(newKeyAlias.data);
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t FuzzHksChangeStorageLevelUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *srcParamSet = nullptr;
    struct HksParamSet *destParamSet = nullptr;
    int32_t ret = HksChangeStorageLevelUnpack(&srcBlob, &keyAlias, &srcParamSet, &destParamSet);
    HKS_FREE(keyAlias.data);
    HksFreeParamSet(&srcParamSet);
    HksFreeParamSet(&destParamSet);
    return ret;
}

static int32_t FuzzHksWrapKeyUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob wrappedKey = { 0, nullptr };
    int32_t ret = HksWrapKeyUnpack(&srcBlob, &keyAlias, &paramSet, &wrappedKey);
    HKS_FREE(keyAlias.data);
    HKS_FREE(wrappedKey.data);
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t FuzzHksUnwrapKeyUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob wrappedKey = { 0, nullptr };
    int32_t ret = HksUnwrapKeyUnpack(&srcBlob, &keyAlias, &paramSet, &wrappedKey);
    HKS_FREE(keyAlias.data);
    HKS_FREE(wrappedKey.data);
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t FuzzHksEncapsulateUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob keyAlias = { 0, nullptr };
    struct HksParamSet *paramSet = nullptr;
    struct HksBlob sharedKeyAlias = { 0, nullptr };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    int32_t ret = HksEncapsulateUnpack(&srcBlob, &keyAlias, &paramSet, &sharedKeyAlias, &sharedKeyParamSet);
    HKS_FREE(keyAlias.data);
    HKS_FREE(sharedKeyAlias.data);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&sharedKeyParamSet);
    return ret;
}

static int32_t FuzzHksDecapsulateUnpack(FuzzedDataProvider &fdp)
{
    uint32_t srcSize = fdp.ConsumeIntegralInRange<uint32_t>(1, MAX_IPC_BUF_SIZE);
    auto srcData = fdp.ConsumeBytes<uint8_t>(srcSize);
    if (srcData.empty()) return HKS_ERROR_INSUFFICIENT_DATA;
    struct HksBlob srcBlob = { static_cast<uint32_t>(srcData.size()), srcData.data() };

    struct HksBlob sharedKeyAlias = { 0, nullptr };
    struct HksParamSet *sharedKeyParamSet = nullptr;
    struct HksBlob encapOrsharedSecret = { 0, nullptr };
    uint32_t offset = 0;
    int32_t ret = HksDecapsulateUnpack(&srcBlob, &sharedKeyAlias, &sharedKeyParamSet,
        &encapOrsharedSecret, &offset);
    HKS_FREE(sharedKeyAlias.data);
    HKS_FREE(encapOrsharedSecret.data);
    HksFreeParamSet(&sharedKeyParamSet);
    return ret;
}

static int32_t FuzzHksEncapsulateResponsePack(FuzzedDataProvider &fdp)
{
    uint32_t encapSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto encapData = fdp.ConsumeBytes<uint8_t>(encapSize);
    if (encapData.empty()) encapData = {0};

    uint32_t secretSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    auto secretData = fdp.ConsumeBytes<uint8_t>(secretSize);
    if (secretData.empty()) secretData = {0};

    struct HksEncapsulationResult encapResult = {};
    encapResult.encapsulatedData = { static_cast<uint32_t>(encapData.size()), encapData.data() };
    encapResult.sharedSecret = { static_cast<uint32_t>(secretData.size()), secretData.data() };

    struct HksBlob responseBlob = { 0, nullptr };
    int32_t ret = HksEncapsulateResponsePack(&encapResult, &responseBlob);
    HKS_FREE(responseBlob.data);
    return ret;
}

static int32_t FuzzHksListAliasesPackFromService(FuzzedDataProvider &fdp)
{
    // null aliasSet
    struct HksBlob destData = { 0, nullptr };
    (void)HksListAliasesPackFromService(nullptr, &destData);

    // empty aliasSet
    struct HksKeyAliasSet emptySet = {};
    emptySet.aliasesCnt = 0;
    emptySet.aliases = nullptr;
    struct HksBlob destData2 = { 0, nullptr };
    (void)HksListAliasesPackFromService(&emptySet, &destData2);

    // with FDP-driven aliases
    uint32_t cnt = fdp.ConsumeIntegralInRange<uint32_t>(1, 8);
    std::vector<std::vector<uint8_t>> aliasStorage(cnt);
    std::vector<struct HksBlob> aliases(cnt);
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t sz = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
        aliasStorage[i] = fdp.ConsumeBytes<uint8_t>(sz);
        if (aliasStorage[i].empty()) aliasStorage[i] = {0};
        aliases[i] = { static_cast<uint32_t>(aliasStorage[i].size()), aliasStorage[i].data() };
    }
    struct HksKeyAliasSet aliasSet = {};
    aliasSet.aliasesCnt = cnt;
    aliasSet.aliases = aliases.data();
    struct HksBlob destData3 = { 0, nullptr };
    int32_t ret = HksListAliasesPackFromService(&aliasSet, &destData3);
    HKS_FREE(destData3.data);
    return ret;
}

static int32_t FuzzHksCertificatesPackFromService(FuzzedDataProvider &fdp)
{
    // null certInfoSet
    struct HksBlob destData = { 0, nullptr };
    (void)HksCertificatesPackFromService(nullptr, &destData);

    // with FDP-driven certs
    uint32_t cnt = fdp.ConsumeIntegralInRange<uint32_t>(1, 4);
    std::vector<std::vector<uint8_t>> indexStorage(cnt);
    std::vector<std::vector<uint8_t>> certStorage(cnt);
    std::vector<struct HksExtCertInfo> certInfos(cnt);
    for (uint32_t i = 0; i < cnt; i++) {
        uint32_t idxSz = fdp.ConsumeIntegralInRange<uint32_t>(1, 16);
        indexStorage[i] = fdp.ConsumeBytes<uint8_t>(idxSz);
        if (indexStorage[i].empty()) indexStorage[i] = {0};

        uint32_t certSz = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
        certStorage[i] = fdp.ConsumeBytes<uint8_t>(certSz);
        if (certStorage[i].empty()) certStorage[i] = {0};

        certInfos[i].index = { static_cast<uint32_t>(indexStorage[i].size()), indexStorage[i].data() };
        certInfos[i].cert = { static_cast<uint32_t>(certStorage[i].size()), certStorage[i].data() };
    }
    struct HksExtCertInfoSet certInfoSet = {};
    certInfoSet.count = cnt;
    certInfoSet.certs = certInfos.data();
    struct HksBlob destData2 = { 0, nullptr };
    int32_t ret = HksCertificatesPackFromService(&certInfoSet, &destData2);
    HKS_FREE(destData2.data);
    return ret;
}

using FuzzFunc = int32_t (*)(FuzzedDataProvider &);

static const FuzzFunc g_fuzzFuncs[] = {
    FuzzHksRenameKeyAliasUnpack,
    FuzzHksChangeStorageLevelUnpack,
    FuzzHksWrapKeyUnpack,
    FuzzHksUnwrapKeyUnpack,
    FuzzHksEncapsulateUnpack,
    FuzzHksDecapsulateUnpack,
    FuzzHksEncapsulateResponsePack,
    FuzzHksListAliasesPackFromService,
    FuzzHksCertificatesPackFromService,
};

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    auto func = fdp.PickValueInArray(g_fuzzFuncs);
    return func(fdp);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
