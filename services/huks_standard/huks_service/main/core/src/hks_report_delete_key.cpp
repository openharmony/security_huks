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

#include "hks_report_delete_key.h"

#include <cstdint>
#include <string>
#include "hks_event_info.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_report_common.h"


int32_t PreConstructDeleteKeyReportParamSet(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    uint64_t startTime, struct HksParamSet **paramSetOut)
{
    HKS_IF_TRUE_LOGI_RETURN(keyAlias == nullptr || paramSetIn == nullptr, HKS_ERROR_NULL_POINTER,
        "PreConstructDeleteKeyReportParamSet params is null")
    int32_t ret = HksInitParamSet(paramSetOut);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "ConstructGenKeyReportParamSet InitParamSet failed")

    do {
        ret = PreAddCommonInfo(*paramSetOut, keyAlias, paramSetIn, startTime);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "pre add common info to params failed!")

        struct HksParam params[] = {
            {
                .tag = HKS_TAG_PARAM1_UINT32,
                .uint32Param = HKS_EVENT_DELETE_KEY
            },
            {
                .tag = HKS_TAG_PARAM0_UINT32,
                .uint32Param = HKS_EVENT_DELETE_KEY
            },
        };
        ret = HksAddParams(*paramSetOut, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "add in params failed!")

        return HKS_SUCCESS;
    } while (0);

    HKS_LOG_E("PreConstructDeleteKeyReportParamSet failed");
    HksFreeParamSet(paramSetOut);
    return ret;
}

int32_t HksParamSetToEventInfoForDelete(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksParamSetToEventInfoForDelete params is null")
    int32_t ret = HKS_SUCCESS;
    do {
        ret = GetCommonEventInfo(paramSetIn, eventInfo);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

        ret = GetEventKeyInfo(paramSetIn, &(eventInfo->keyInfo));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "report GetEventKeyInfo failed!  ret = %" LOG_PUBLIC "d", ret);

        return HKS_SUCCESS;
    } while (0);

    HKS_LOG_E("report ParamSetToEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);
    FreeEventInfoSpecificPtr(eventInfo);
    return ret;
}

bool HksEventInfoIsNeedReportForDelete(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS) &&
        (eventInfo->common.result.code != HKS_ERROR_NOT_EXIST));
}

bool HksEventInfoIsEqualForDelete(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    HKS_IF_NOT_TRUE_RETURN(CheckEventCommon(eventInfo1, eventInfo2), false)
    return eventInfo1->keyInfo.aliasHash == eventInfo2->keyInfo.aliasHash;
}

void HksEventInfoAddForDelete(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksEventInfoIsEqualForDelete(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksEventInfoToMapForDelete(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "HksEventInfoToMapForDelete evenInfo is null")
    auto ret = EventInfoToMapKeyInfo(&eventInfo->keyInfo, reportData);
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL,
        "HksEventInfoToMapForDelete failed! reportData insert failed!")
    return HKS_SUCCESS;
}