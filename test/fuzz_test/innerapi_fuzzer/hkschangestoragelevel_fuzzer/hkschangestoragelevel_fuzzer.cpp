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

#include "hkschangestoragelevel_fuzzer.h"

#include "hks_fuzz_util.h"
#include "hks_type_enum.h"

namespace OHOS {
namespace Security {
namespace Hks {

static uint32_t PickRandomAuthStorageLevel(FuzzedDataProvider &fdp) {
    if (fdp.ConsumeBool()) {
        return fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
    }
    static const uint32_t kAuthStorageLevel[] = {
        HKS_AUTH_STORAGE_LEVEL_DE,
        HKS_AUTH_STORAGE_LEVEL_CE,
        HKS_AUTH_STORAGE_LEVEL_ECE,
    };
    return fdp.PickValueInArray(kAuthStorageLevel);
}

static void AddSomeParams(FuzzedDataProvider &fdp, WrapParamSet &ps,
    [[maybe_unused]] std::vector<std::vector<uint8_t>> &blobStorage)
{
    std::vector<struct HksParam> params;

    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t storageLevel = PickRandomAuthStorageLevel(fdp);
        params.push_back({ .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = storageLevel });
    }

    if (fdp.ConsumeProbability<double>() < 0.99) {
        uint32_t userId = fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
        params.push_back({ .tag = HKS_TAG_SPECIFIC_USER_ID, .uint32Param = userId });
    }

    if (!params.empty()) {
        HksAddParams(ps.s, params.data(), params.size());
    }
}

WrapParamSet ConstructChangeStorageLevelParamSet(FuzzedDataProvider &fdp)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }

    std::vector<std::vector<uint8_t>> blobStorage;
    AddSomeParams(fdp, ps, blobStorage);

    (void)HksBuildParamSet(&ps.s);
    return ps;
}

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> alias = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (alias.size() == 0) {
        alias = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(alias.size()), alias.data() };

    (void)HksFuzzGenerateKey(fdp, keyAlias);

    WrapParamSet srcPs = ConstructParamSetAddFuzzData(ConstructChangeStorageLevelParamSet(fdp), fdp);
    WrapParamSet destPs = ConstructParamSetAddFuzzData(ConstructChangeStorageLevelParamSet(fdp), fdp);

    return HksChangeStorageLevel(&keyAlias, srcPs.s, destPs.s);
}
}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    return OHOS::Security::Hks::HksFuzzInitWithGoldenPath();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}

