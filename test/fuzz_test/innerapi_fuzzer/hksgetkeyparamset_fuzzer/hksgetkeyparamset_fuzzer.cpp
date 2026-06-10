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

#include "hksgetkeyparamset_fuzzer.h"

#include <cstring>

#include "hks_fuzz_util.h"
#include "hks_param.h"
#include "hks_type_inner.h"

namespace OHOS {
namespace Security {
namespace Hks {

/* ========== Fuzz HksAddParamsWithFilter ========== */
static int32_t FuzzAddParamsWithFilter(FuzzedDataProvider &fdp)
{
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint32_t paramCnt = fdp.ConsumeIntegralInRange<uint32_t>(0, 20);
    std::vector<struct HksParam> params(paramCnt);
    std::vector<std::vector<uint8_t>> blobStorage;

    for (uint32_t i = 0; i < paramCnt; i++) {
        uint32_t tagChoice = fdp.ConsumeIntegralInRange<uint32_t>(0, 4);
        switch (tagChoice) {
            case 0:
                params[i].tag = HKS_TAG_KEY_OVERRIDE;
                params[i].boolParam = fdp.ConsumeBool();
                break;
            case 1:
                params[i].tag = HKS_TAG_ALGORITHM;
                params[i].uint32Param = fdp.ConsumeIntegral<uint32_t>();
                break;
            case 2:
                params[i].tag = HKS_TAG_KEY_SIZE;
                params[i].uint32Param = fdp.ConsumeIntegral<uint32_t>();
                break;
            case 3: {
                params[i].tag = HKS_TAG_KEY_ALIAS;
                uint32_t size = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
                auto data = fdp.ConsumeBytes<uint8_t>(size);
                blobStorage.push_back(std::move(data));
                params[i].blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() };
                break;
            }
            default:
                params[i].tag = fdp.ConsumeIntegral<uint32_t>();
                params[i].uint32Param = fdp.ConsumeIntegral<uint32_t>();
                break;
        }
    }

    if (paramCnt > 0) {
        ret = HksAddParamsWithFilter(paramSet, params.data(), paramCnt);
    }

    if (paramCnt > 1) {
        struct HksParamSet *paramSet2 = nullptr;
        if (HksInitParamSet(&paramSet2) == HKS_SUCCESS) {
            (void)HksAddParamsWithFilter(paramSet2, params.data(), paramCnt / 2);
            HksFreeParamSet(&paramSet2);
        }
    }

    HksFreeParamSet(&paramSet);
    return ret;
}

/* ========== Fuzz HksFreeKeyAliasSet ========== */
static int32_t FuzzFreeKeyAliasSet(FuzzedDataProvider &fdp)
{
    HksFreeKeyAliasSet(nullptr);

    auto *aliasSet1 = static_cast<struct HksKeyAliasSet *>(malloc(sizeof(struct HksKeyAliasSet)));
    if (aliasSet1 != nullptr) {
        aliasSet1->aliasesCnt = 0;
        aliasSet1->aliases = nullptr;
        HksFreeKeyAliasSet(aliasSet1);
    }

    uint32_t cnt = fdp.ConsumeIntegralInRange<uint32_t>(1, 10);
    size_t structSize = sizeof(struct HksKeyAliasSet) + cnt * sizeof(struct HksBlob);
    auto *aliasSet2 = static_cast<struct HksKeyAliasSet *>(malloc(structSize));
    if (aliasSet2 != nullptr) {
        aliasSet2->aliasesCnt = cnt;
        aliasSet2->aliases = reinterpret_cast<struct HksBlob *>(
            reinterpret_cast<uint8_t *>(aliasSet2) + sizeof(struct HksKeyAliasSet));

        std::vector<std::vector<uint8_t>> storage;
        for (uint32_t i = 0; i < cnt; i++) {
            uint32_t blobSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
            auto data = fdp.ConsumeBytes<uint8_t>(blobSize);
            storage.push_back(std::move(data));
            aliasSet2->aliases[i].size = static_cast<uint32_t>(storage.back().size());
            aliasSet2->aliases[i].data = storage.back().data();
        }
        HksFreeKeyAliasSet(aliasSet2);
    }

    return HKS_SUCCESS;
}

/* ========== Fuzz HksGetParam ========== */
static int32_t FuzzGetParam(FuzzedDataProvider &fdp)
{
    struct HksParam *param = nullptr;
    (void)HksGetParam(nullptr, 0, &param);
    (void)HksGetParam(nullptr, 0, nullptr);

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    uint32_t tagsToTry[] = {
        HKS_TAG_ALGORITHM, HKS_TAG_KEY_SIZE, HKS_TAG_PURPOSE,
        HKS_TAG_DIGEST, HKS_TAG_PADDING, HKS_TAG_BLOCK_MODE,
        fdp.ConsumeIntegral<uint32_t>(),
    };

    for (auto tag : tagsToTry) {
        struct HksParam *outParam = nullptr;
        (void)HksGetParam(ps.s, tag, &outParam);
    }

    return HKS_SUCCESS;
}

/* ========== Fuzz HksCheckParamMatch ========== */
static int32_t FuzzCheckParamMatch(FuzzedDataProvider &fdp)
{
    (void)HksCheckParamMatch(nullptr, nullptr);
    struct HksParam p = { .tag = HKS_TAG_ALGORITHM, .uint32Param = 1 };
    (void)HksCheckParamMatch(&p, nullptr);
    (void)HksCheckParamMatch(nullptr, &p);

    std::vector<std::vector<uint8_t>> storage;
    auto makeParam = [&fdp, &storage](uint32_t tag) -> struct HksParam {
        struct HksParam param = {};
        param.tag = tag;
        switch (GetTagType((enum HksTag)tag)) {
            case HKS_TAG_TYPE_INT:
                param.int32Param = fdp.ConsumeIntegral<int32_t>();
                break;
            case HKS_TAG_TYPE_UINT:
                param.uint32Param = fdp.ConsumeIntegral<uint32_t>();
                break;
            case HKS_TAG_TYPE_ULONG:
                param.uint64Param = fdp.ConsumeIntegral<uint64_t>();
                break;
            case HKS_TAG_TYPE_BOOL:
                param.boolParam = fdp.ConsumeBool();
                break;
            case HKS_TAG_TYPE_BYTES: {
                uint32_t size = fdp.ConsumeIntegralInRange<uint32_t>(1, 16);
                auto data = fdp.ConsumeBytes<uint8_t>(size);
                storage.push_back(std::move(data));
                param.blob = { static_cast<uint32_t>(storage.back().size()), storage.back().data() };
                break;
            }
            default:
                param.uint32Param = fdp.ConsumeIntegral<uint32_t>();
                break;
        }
        return param;
    };

    uint32_t numPairs = fdp.ConsumeIntegralInRange<uint32_t>(1, 8);
    for (uint32_t i = 0; i < numPairs; i++) {
        uint32_t tag = fdp.ConsumeIntegral<uint32_t>();
        struct HksParam param1 = makeParam(tag);
        struct HksParam param2 = makeParam(tag);
        (void)HksCheckParamMatch(&param1, &param2);

        uint32_t tag2 = fdp.ConsumeIntegral<uint32_t>();
        struct HksParam param3 = makeParam(tag2);
        (void)HksCheckParamMatch(&param1, &param3);
    }

    return HKS_SUCCESS;
}

/* ========== Fuzz HksCheckIsTagAlreadyExist ========== */
static int32_t FuzzCheckIsTagAlreadyExist(FuzzedDataProvider &fdp)
{
    (void)HksCheckIsTagAlreadyExist(nullptr, 0, nullptr);

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    uint32_t numTags = fdp.ConsumeIntegralInRange<uint32_t>(1, 10);
    std::vector<struct HksParam> checkParams(numTags);
    for (uint32_t i = 0; i < numTags; i++) {
        checkParams[i].tag = fdp.ConsumeIntegral<uint32_t>();
        checkParams[i].uint32Param = 0;
    }

    (void)HksCheckIsTagAlreadyExist(checkParams.data(), numTags, ps.s);

    struct HksParam existCheck[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = 0 },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = 0 },
    };
    (void)HksCheckIsTagAlreadyExist(existCheck, HKS_ARRAY_SIZE(existCheck), ps.s);

    return HKS_SUCCESS;
}

/* ========== Fuzz HksDeleteTagsFromParamSet ========== */
static int32_t FuzzDeleteTagsFromParamSet(FuzzedDataProvider &fdp)
{
    struct HksParamSet *outParamSet = nullptr;
    uint32_t tag = HKS_TAG_ALGORITHM;
    (void)HksDeleteTagsFromParamSet(nullptr, 0, nullptr, nullptr);
    (void)HksDeleteTagsFromParamSet(&tag, 1, nullptr, &outParamSet);

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    uint32_t numTags = fdp.ConsumeIntegralInRange<uint32_t>(1, 5);
    std::vector<uint32_t> tagsToDelete(numTags);
    for (uint32_t i = 0; i < numTags; i++) {
        tagsToDelete[i] = fdp.ConsumeIntegral<uint32_t>();
    }

    struct HksParamSet *result = nullptr;
    int32_t ret = HksDeleteTagsFromParamSet(tagsToDelete.data(), numTags, ps.s, &result);
    if (ret == HKS_SUCCESS && result != nullptr) {
        HksFreeParamSet(&result);
    }

    uint32_t commonTags[] = { HKS_TAG_ALGORITHM, HKS_TAG_KEY_SIZE, HKS_TAG_PURPOSE };
    struct HksParamSet *result2 = nullptr;
    ret = HksDeleteTagsFromParamSet(commonTags, HKS_ARRAY_SIZE(commonTags), ps.s, &result2);
    if (ret == HKS_SUCCESS && result2 != nullptr) {
        HksFreeParamSet(&result2);
    }

    return ret;
}

/* ========== Original HksGetKeyParamSet fuzz ========== */
static int32_t FuzzGetKeyParamSet(FuzzedDataProvider &fdp)
{
    uint32_t aliasSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    std::vector<uint8_t> aliasBuf = fdp.ConsumeBytes<uint8_t>(aliasSize);
    if (aliasBuf.size() == 0) {
        aliasBuf = std::vector<uint8_t>(1, 0);
    }
    struct HksBlob keyAlias = { static_cast<uint32_t>(aliasBuf.size()), aliasBuf.data() };

    if (fdp.ConsumeBool()) {
        (void)HksFuzzGenerateKey(fdp, keyAlias);
    }

    WrapParamSet psIn = ConstructParamSetFromFdp(fdp);

    uint32_t outSize = fdp.ConsumeIntegralInRange<uint32_t>(64, 1024);
    std::vector<uint8_t> outBuf(outSize);
    struct HksParamSet *paramSetOut = reinterpret_cast<struct HksParamSet *>(outBuf.data());
    paramSetOut->paramSetSize = static_cast<uint32_t>(outBuf.size());

    return HksGetKeyParamSet(&keyAlias, psIn.s, paramSetOut);
}

using FuzzFunc = int32_t (*)(FuzzedDataProvider &);
static const FuzzFunc g_fuzzFuncs[] = {
    FuzzGetKeyParamSet,
    FuzzAddParamsWithFilter,
    FuzzFreeKeyAliasSet,
    FuzzGetParam,
    FuzzCheckParamMatch,
    FuzzCheckIsTagAlreadyExist,
    FuzzDeleteTagsFromParamSet,
};

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    auto fuzzFunc = fdp.PickValueInArray(g_fuzzFuncs);
    return fuzzFunc(fdp);
}

}}}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    struct HksBlob rsaAlias = { 22, reinterpret_cast<uint8_t *>(const_cast<char *>("fuzz_getparamset_rsa")) };
    WrapParamSet genPs = BuildFixedParamSet({ { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS } });
    int32_t ret = HksGenerateKey(&rsaAlias, genPs.s, nullptr);
    printf("fuzz_getkeyparamset init: GenerateKey ret=%d\n", ret);

    uint8_t paramSetOutBuf[512] = {0};
    struct HksParamSet *paramSetOut = reinterpret_cast<struct HksParamSet *>(paramSetOutBuf);
    paramSetOut->paramSetSize = 512;
    WrapParamSet getPs = BuildFixedParamSet({});
    ret = HksGetKeyParamSet(&rsaAlias, getPs.s, paramSetOut);
    printf("fuzz_getkeyparamset init: HksGetKeyParamSet ret=%d\n", ret);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);
    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}