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
#include <unordered_map>
#include <cstring>

#include "hks_log.h"
#include "hks_param.h"

#include "hks_report_wrapper.h"
#include "hks_report_common.h"
#include "hks_report_check_key_exited.h"
#include "hks_report_delete_key.h"
#include "hks_report_import_key.h"
#include "hks_report_list_aliases.h"
#include "hks_event_info.h"
#include "hks_ha_plugin.h"
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

    WrapParamSet ps = ConstructParamSetFromFdp(fdp);

    uint32_t funcNameSize = fdp.ConsumeIntegralInRange<uint32_t>(0, 64);
    auto funcNameData = fdp.ConsumeBytes<uint8_t>(funcNameSize);
    std::string funcNameStr(funcNameData.begin(), funcNameData.end());
    const char *funcName = funcNameStr.empty() ? "fuzz" : funcNameStr.c_str();

    int32_t errorCode = fdp.ConsumeIntegral<int32_t>();

    return ReportFaultEvent(funcName, &processInfo, ps.s, errorCode);
}

// ========== Report event fuzz functions ==========

static WrapParamSet BuildReportParamSet(FuzzedDataProvider &fdp)
{
    WrapParamSet ps{};
    if (HksInitParamSet(&ps.s) != HKS_SUCCESS) {
        return ps;
    }

    std::vector<std::vector<uint8_t>> blobStorage;

    {
        struct HksParam p = { .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = fdp.ConsumeIntegralInRange<uint32_t>(1, 48) };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam p = { .tag = HKS_TAG_PARAM1_UINT32,
            .uint32Param = fdp.ConsumeIntegral<uint32_t>() };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam p = { .tag = HKS_TAG_PARAM2_UINT32,
            .uint32Param = fdp.ConsumeIntegral<uint32_t>() };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam p = { .tag = HKS_TAG_PARAM3_UINT32,
            .uint32Param = fdp.ConsumeIntegral<uint32_t>() };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam p = { .tag = HKS_TAG_PARAM4_UINT32,
            .uint32Param = fdp.ConsumeIntegral<uint32_t>() };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam p = { .tag = HKS_TAG_PARAM5_UINT32,
            .uint32Param = fdp.ConsumeIntegralInRange<uint32_t>(0, 65535) };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        std::string funcName = "fuzzFunc";
        blobStorage.emplace_back(funcName.begin(), funcName.end());
        struct HksParam p = { .tag = HKS_TAG_PARAM0_BUFFER,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        std::string callerName = "fuzzCaller";
        blobStorage.emplace_back(callerName.begin(), callerName.end());
        struct HksParam p = { .tag = HKS_TAG_PARAM2_BUFFER,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct timespec ts = {};
        ts.tv_sec = fdp.ConsumeIntegralInRange<int64_t>(0, 9999999);
        ts.tv_nsec = fdp.ConsumeIntegralInRange<long>(0, 999999999);
        blobStorage.emplace_back(sizeof(struct timespec));
        (void)memcpy_s(blobStorage.back().data(), sizeof(struct timespec), &ts, sizeof(struct timespec));
        struct HksParam p = { .tag = HKS_TAG_PARAM1_BUFFER,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksEventResultInfo resultInfo = {};
        resultInfo.code = fdp.ConsumeIntegral<int32_t>();
        resultInfo.module = fdp.ConsumeIntegral<uint32_t>();
        resultInfo.stage = fdp.ConsumeIntegral<uint32_t>();
        resultInfo.errMsg = nullptr;
        blobStorage.emplace_back(sizeof(struct HksEventResultInfo));
        (void)memcpy_s(blobStorage.back().data(), sizeof(struct HksEventResultInfo),
            &resultInfo, sizeof(struct HksEventResultInfo));
        struct HksParam p = { .tag = HKS_TAG_PARAM3_BUFFER,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        std::string errMsg = "fuzz error";
        blobStorage.emplace_back(errMsg.begin(), errMsg.end());
        struct HksParam p = { .tag = HKS_TAG_PARAM0_NULL,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        std::string group = "fuzzGroup";
        blobStorage.emplace_back(group.begin(), group.end());
        struct HksParam p = { .tag = HKS_TAG_PARAM1_NULL,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        std::string devId = "fuzzDev";
        blobStorage.emplace_back(devId.begin(), devId.end());
        struct HksParam p = { .tag = HKS_TAG_PARAM2_NULL,
            .blob = { static_cast<uint32_t>(blobStorage.back().size()), blobStorage.back().data() } };
        (void)HksAddParams(ps.s, &p, 1);
    }
    {
        struct HksParam params[] = {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_KEY_FLAG, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_KEY_SECURITY_LEVEL, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = fdp.ConsumeIntegral<int32_t>() },
            { .tag = HKS_TAG_IS_BATCH_OPERATION, .boolParam = fdp.ConsumeBool() },
            { .tag = HKS_TAG_BATCH_PURPOSE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_BATCH_OPERATION_TIMEOUT, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
        };
        (void)HksAddParams(ps.s, params, HKS_ARRAY_SIZE(params));
    }
    {
        struct HksParam accessParams[] = {
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_KEY_AUTH_ACCESS_TYPE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_CHALLENGE_TYPE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_CHALLENGE_POS, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_KEY_AUTH_PURPOSE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_FRONT_USER_ID, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_USER_AUTH_MODE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_IS_DEVICE_PASSWORD_SET, .boolParam = fdp.ConsumeBool() },
        };
        (void)HksAddParams(ps.s, accessParams, HKS_ARRAY_SIZE(accessParams));
    }
    {
        struct HksParam importParams[] = {
            { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
            { .tag = HKS_TAG_UNWRAP_ALGORITHM_SUITE, .uint32Param = fdp.ConsumeIntegral<uint32_t>() },
        };
        (void)HksAddParams(ps.s, importParams, HKS_ARRAY_SIZE(importParams));
    }
    {
        struct HksParam p = { .tag = HKS_TAG_TRACE_ID,
            .uint64Param = fdp.ConsumeIntegral<uint64_t>() };
        (void)HksAddParams(ps.s, &p, 1);
    }

    (void)HksBuildParamSet(&ps.s);
    return ps;
}

static int32_t FuzzCheckKeyExitedReport(FuzzedDataProvider &fdp)
{
    WrapParamSet ps = BuildReportParamSet(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    struct HksEventInfo eventInfo1 = {};
    int32_t ret = HksParamSetToEventInfoForCheckKeyExited(ps.s, &eventInfo1);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    (void)HksEventInfoIsNeedReportForCheckKeyExited(&eventInfo1);
    (void)HksEventInfoIsNeedReportForCheckKeyExited(nullptr);

    struct HksEventInfo eventInfo2 = {};
    ret = HksParamSetToEventInfoForCheckKeyExited(ps.s, &eventInfo2);
    if (ret == HKS_SUCCESS) {
        (void)HksEventInfoIsEqualForCheckKeyExited(&eventInfo1, &eventInfo2);
        HksEventInfoAddForCheckKeyExited(&eventInfo1, &eventInfo2);
    }

    std::unordered_map<std::string, std::string> reportData;
    (void)HksEventInfoToMapForCheckKeyExited(&eventInfo1, reportData);
    (void)HksEventInfoToMapForCheckKeyExited(nullptr, reportData);

    FreeCommonEventInfo(&eventInfo1);
    FreeCommonEventInfo(&eventInfo2);
    return ret;
}

static int32_t FuzzDeleteReport(FuzzedDataProvider &fdp)
{
    WrapParamSet ps = BuildReportParamSet(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    struct HksEventInfo eventInfo1 = {};
    int32_t ret = HksParamSetToEventInfoForDelete(ps.s, &eventInfo1);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    (void)HksEventInfoIsNeedReportForDelete(&eventInfo1);
    (void)HksEventInfoIsNeedReportForDelete(nullptr);

    struct HksEventInfo eventInfo2 = {};
    ret = HksParamSetToEventInfoForDelete(ps.s, &eventInfo2);
    if (ret == HKS_SUCCESS) {
        (void)HksEventInfoIsEqualForDelete(&eventInfo1, &eventInfo2);
        HksEventInfoAddForDelete(&eventInfo1, &eventInfo2);
    }

    std::unordered_map<std::string, std::string> reportData;
    (void)HksEventInfoToMapForDelete(&eventInfo1, reportData);
    (void)HksEventInfoToMapForDelete(nullptr, reportData);

    FreeCommonEventInfo(&eventInfo1);
    FreeCommonEventInfo(&eventInfo2);
    return ret;
}

static int32_t FuzzImportReport(FuzzedDataProvider &fdp)
{
    WrapParamSet ps = BuildReportParamSet(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    struct HksEventInfo eventInfo1 = {};
    int32_t ret = HksParamSetToEventInfoForImport(ps.s, &eventInfo1);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    (void)HksEventInfoIsNeedReportForImport(&eventInfo1);
    (void)HksEventInfoIsNeedReportForImport(nullptr);

    struct HksEventInfo eventInfo2 = {};
    ret = HksParamSetToEventInfoForImport(ps.s, &eventInfo2);
    if (ret == HKS_SUCCESS) {
        (void)HksEventInfoIsEqualForImport(&eventInfo1, &eventInfo2);
        HksEventInfoAddForImport(&eventInfo1, &eventInfo2);
    }

    std::unordered_map<std::string, std::string> reportData;
    (void)HksEventInfoToMapForImport(&eventInfo1, reportData);
    (void)HksEventInfoToMapForImport(nullptr, reportData);

    FreeCommonEventInfo(&eventInfo1);
    FreeCommonEventInfo(&eventInfo2);
    return ret;
}

static int32_t FuzzListAliasesReport(FuzzedDataProvider &fdp)
{
    WrapParamSet ps = BuildReportParamSet(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    struct HksEventInfo eventInfo1 = {};
    int32_t ret = HksParamSetToEventInfoForListAliases(ps.s, &eventInfo1);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    (void)HksEventInfoIsNeedReportForListAliases(&eventInfo1);
    (void)HksEventInfoIsNeedReportForListAliases(nullptr);

    struct HksEventInfo eventInfo2 = {};
    ret = HksParamSetToEventInfoForListAliases(ps.s, &eventInfo2);
    if (ret == HKS_SUCCESS) {
        (void)HksEventInfoIsEqualForListAliases(&eventInfo1, &eventInfo2);
        HksEventInfoAddForListAliases(&eventInfo1, &eventInfo2);
    }

    std::unordered_map<std::string, std::string> reportData;
    (void)HksEventInfoToMapForListAliases(&eventInfo1, reportData);
    (void)HksEventInfoToMapForListAliases(nullptr, reportData);

    FreeCommonEventInfo(&eventInfo1);
    FreeCommonEventInfo(&eventInfo2);
    return ret;
}

static int32_t FuzzReportCommon(FuzzedDataProvider &fdp)
{
    WrapParamSet ps = BuildReportParamSet(fdp);
    if (ps.s == nullptr) {
        return HKS_FAILURE;
    }

    struct HksEventInfo eventInfo = {};
    int32_t ret = GetCommonEventInfo(ps.s, &eventInfo);
    if (ret == HKS_SUCCESS) {
        struct HksEventKeyInfo keyInfo = {};
        (void)GetEventKeyInfo(ps.s, &keyInfo);

        struct HksEventKeyAccessInfo accessInfo = {};
        (void)GetEventKeyAccessInfo(ps.s, &accessInfo);

        std::unordered_map<std::string, std::string> reportData;
        (void)EventInfoToMapKeyInfo(&keyInfo, reportData);
        (void)EventInfoToMapKeyAccessInfo(&accessInfo, reportData);

        struct HksEventInfo eventInfo2 = {};
        ret = GetCommonEventInfo(ps.s, &eventInfo2);
        if (ret == HKS_SUCCESS) {
            (void)CheckEventCommon(&eventInfo, &eventInfo2);
            (void)CheckEventCommon(nullptr, &eventInfo2);
            (void)CheckEventCommon(&eventInfo, nullptr);
            (void)CheckEventCommonAndKey(&eventInfo, &eventInfo2);
        }

        FreeCommonEventInfo(&eventInfo2);
    }

    (void)GetCommonEventInfo(nullptr, nullptr);
    (void)GetEventKeyInfo(nullptr, nullptr);
    (void)GetEventKeyAccessInfo(nullptr, nullptr);

    std::unordered_map<std::string, std::string> emptyMap;
    (void)EventInfoToMapKeyInfo(nullptr, emptyMap);
    (void)EventInfoToMapKeyAccessInfo(nullptr, emptyMap);

    (void)CopyParamBlobData(nullptr, nullptr);
    char *dst = nullptr;
    (void)CopyParamBlobData(&dst, nullptr);

    FreeCommonEventInfo(&eventInfo);
    return ret;
}

/* ========== Fuzz HA Plugin functions ========== */
static int32_t FuzzHaPluginRegisterAndEnqueue(FuzzedDataProvider &fdp)
{
    // Test HksRegisterEventProcWrapper with null
    (void)HksRegisterEventProcWrapper(nullptr);

    // Test HksRegisterEventProcs with null/zero
    (void)HksRegisterEventProcs(nullptr, 0);

    // Test HksEnqueueEventWrapper with null paramSet
    (void)HksEnqueueEventWrapper(fdp.ConsumeIntegral<uint32_t>(), nullptr);

    // Build a valid paramSet and enqueue
    WrapParamSet ps = ConstructParamSetFromFdp(fdp);
    uint32_t eventId = fdp.ConsumeIntegralInRange<uint32_t>(1, 48);
    if (ps.s != nullptr) {
        (void)HksEnqueueEventWrapper(eventId, ps.s);
    }

    return HKS_SUCCESS;
}

using FuzzFunc = int32_t (*)(FuzzedDataProvider &);

static const FuzzFunc g_fuzzFuncs[] = {
    FuzzReportFaultEvent,
    FuzzCheckKeyExitedReport,
    FuzzDeleteReport,
    FuzzImportReport,
    FuzzListAliasesReport,
    FuzzReportCommon,
    FuzzHaPluginRegisterAndEnqueue,
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
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t ret = OHOS::Security::Hks::DoSomethingInterestingWithMyAPI(fdp);

    OHOS::Security::Hks::FuzzStatsRecord(ret);
    return 0;
}
