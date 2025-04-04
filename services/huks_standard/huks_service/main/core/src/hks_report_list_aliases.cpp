/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_report_list_aliases.h"

#include <cstdint>
#include <string>
#include "hks_event_info.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_report_common.h"


int32_t PreConstructListAliasesReportParamSet(const struct HksParamSet *paramSetIn, uint64_t startTime,
    struct HksParamSet **paramSetOut)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "PreConstructListAliasesReportParamSet params is null")
    int32_t ret = HksInitParamSet(paramSetOut);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreConstructListAliasesReportParamSet InitParamSet failed")

    do {
        ret = AddTimeCost(*paramSetOut, startTime);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreAddCommonInfo add time cost to paramSetOut failed!")

        ret = HksAddParams(*paramSetOut, paramSetIn->params, paramSetIn->paramsCnt);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreAddCommonInfo add paramSetIn params to paramSetOut failed!")

        struct HksParam params[] = {
            {
                .tag = HKS_TAG_PARAM1_UINT32,
                .uint32Param = HKS_EVENT_LIST_ALIASES
            },
            {
                .tag = HKS_TAG_PARAM0_UINT32,
                .uint32Param = HKS_EVENT_LIST_ALIASES
            },
        };
        ret = HksAddParams(*paramSetOut, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "add in params failed!")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("PreConstructListAliasesReportParamSet failed");
        HksFreeParamSet(paramSetOut);
    }
    return ret;
}

int32_t HksParamSetToEventInfoForListAliases(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksParamSetToEventInfoForListAliases params is null")
    int32_t ret = HKS_SUCCESS;
    do {
        ret = GetCommonEventInfo(paramSetIn, eventInfo);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

        ret = GetEventKeyInfo(paramSetIn, &(eventInfo->keyInfo));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "report GetEventKeyInfo failed!  ret = %" LOG_PUBLIC "d", ret);
    } while (0);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("report ParamSetToEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);
        FreeEventInfoSpecificPtr(eventInfo);
    }
    return ret;
}

bool HksEventInfoIsNeedReportForListAliases(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksEventInfoIsEqualForListAliases(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return CheckEventCommon(eventInfo1, eventInfo2);
}

void HksEventInfoAddForListAliases(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksEventInfoIsEqualForListAliases(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksEventInfoToMapForListAliases(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "HksEventInfoToMapForImport evenInfo is null")
    auto ret = EventInfoToMapKeyInfo(&eventInfo->keyInfo, reportData);
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL,
        "HksEventInfoToMapForImport failed! reportData insert failed!")
    return HKS_SUCCESS;
}