/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hksreportwrapper_fuzzer.h"

#include <string>
#include <vector>

#include "hks_log.h"
#include "hks_param.h"

#include "hks_report_wrapper.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_inner.h"

#include "hks_fuzz_util.h"

const std::string TEST_PROCESS_NAME = "test_process";
const std::string TEST_USER_ID = "123465";
static const struct HksParam g_genParams[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_128 },
    { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
};

namespace OHOS {
namespace Security {
namespace Hks {

static int32_t BuildParamSet(const struct HksParam *param, uint32_t paramCnt, struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (param != nullptr && paramCnt > 0) {
            ret = HksAddParams(paramSet, param, paramCnt);
            HKS_IF_NOT_SUCC_BREAK(ret)
        }

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    *paramSetOut = paramSet;
    return HKS_SUCCESS;
}

static void HksReportWrapperTest001()
{
    ReportFaultEvent(nullptr, nullptr, nullptr, HKS_SUCCESS);
}

static void HksReportWrapperTest002()
{
    HksBlob processName = {
        .size = TEST_PROCESS_NAME.size() + 1,
        .data = (uint8_t *)&TEST_PROCESS_NAME[0],
    };
    HksBlob userId = {
        .size = TEST_USER_ID.size() + 1,
        .data = (uint8_t *)&TEST_USER_ID[0]
    };
    HksProcessInfo hksProcessInfo = {
        .userId = userId,
        .processName = processName
    };

    struct HksParamSet *paramSet = nullptr;
    BuildParamSet(g_genParams, HKS_ARRAY_SIZE(g_genParams), &paramSet);

    ReportFaultEvent(__func__, &hksProcessInfo, paramSet, HKS_FAILURE);
    HksFreeParamSet(&paramSet);
}

// ========== FDP-driven fuzz functions (supplement existing hardcoded tests) ==========

static int32_t FuzzReportFaultEvent(FuzzedDataProvider &fdp)
{
    // Build processInfo from FDP
    uint32_t nameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    auto nameData = fdp.ConsumeBytes<uint8_t>(nameSize);
    std::string processNameStr(nameData.begin(), nameData.end());

    uint32_t uidVal = fdp.ConsumeIntegralInRange<uint32_t>(0, 999);
    std::string userIdStr = std::to_string(uidVal);

    HksProcessInfo processInfo = {};
    processInfo.processName = { static_cast<uint32_t>(processNameStr.size()),
                                reinterpret_cast<uint8_t *>(processNameStr.data()) };
    processInfo.userId = { static_cast<uint32_t>(userIdStr.size()),
                           reinterpret_cast<uint8_t *>(userIdStr.data()) };
    processInfo.userIdInt = uidVal;
    processInfo.uidInt = fdp.ConsumeIntegralInRange<uint32_t>(0, 999);
    processInfo.accessTokenId = fdp.ConsumeIntegralInRange<uint32_t>(0, 999);

    // Build ParamSet from FDP
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    // Fuzz funcName and errorCode
    uint32_t funcNameSize = fdp.ConsumeIntegralInRange<uint32_t>(0, 64);
    auto funcNameData = fdp.ConsumeBytes<uint8_t>(funcNameSize);
    std::string funcNameStr(funcNameData.begin(), funcNameData.end());
    const char *funcName = funcNameStr.empty() ? nullptr : funcNameStr.c_str();

    int32_t errorCode = fdp.ConsumeIntegral<int32_t>();

    return ReportFaultEvent(funcName, &processInfo, ps.s, errorCode);
}

using FuzzFunc = int32_t (*)(FuzzedDataProvider &);

static const FuzzFunc g_fuzzFuncs[1] = {
    FuzzReportFaultEvent,
};

// Existing hardcoded test function pointers for selective execution
using HardcodedFunc = void (*)();
static const HardcodedFunc g_hardcodedFuncs[2] = {
    HksReportWrapperTest001,
    HksReportWrapperTest002,
};

int32_t DoSomethingInterestingWithMyAPI(FuzzedDataProvider &fdp)
{
    // Execute 1 hardcoded function to preserve existing coverage
    auto func = fdp.PickValueInArray(g_hardcodedFuncs);
    func();

    // Execute 1 FDP-driven function to explore new paths
    auto fuzzFunc = fdp.PickValueInArray(g_fuzzFuncs);
    return fuzzFunc(fdp);
}
}
}
}

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
