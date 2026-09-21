/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_report_sa_event.h"

#include <cstring>
#include <ctime>
#include <memory>

#include "hks_ha_event_report.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_report_common.h"
#include "hks_template.h"

int32_t HksParamSetToEventInfoForSaEvent(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGE_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER, "params is null")

    std::unique_ptr<struct HksEventInfo, DeleteEventCommonInfo> commEventInfo(eventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret)

    (void)commEventInfo.release();
    return HKS_SUCCESS;
}

bool HksEventInfoIsNeedReportForSaEvent(const struct HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, false, "eventInfo is null")
    /* this event is enqueued only when the subscribe fails, so it always needs to be reported */
    return true;
}

bool HksEventInfoIsEqualForSaEvent(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2)
{
    return CheckEventCommon(eventInfo1, eventInfo2);
}

void HksEventInfoAddForSaEvent(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (!HksEventInfoIsEqualForSaEvent(dstEventInfo, srcEventInfo)) {
        return;
    }
    dstEventInfo->common.count++;
    dstEventInfo->common.time = srcEventInfo->common.time;
}

int32_t HksEventInfoToMapForSaEvent(const struct HksEventInfo *eventInfo,
    [[maybe_unused]] std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "HksEventInfoToMapForSaEvent evenInfo is null")
    return HKS_SUCCESS;
}

void ReportSubscribeSystemEventFail(const char *funcName, int32_t errorCode)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(funcName, "ReportSubscribeSystemEventFail: funcName is null")

    struct HksParamSet *reportParamSet = nullptr;
    int32_t ret = HksInitParamSet(&reportParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(ret, "init report paramset fail")

    do {
        struct timespec time = {0};
        (void)timespec_get(&time, TIME_UTC);
        struct HksEventResultInfo resultInfo = {
            .code = errorCode,
            .module = 0,
            .stage = 0,
            .errMsg = nullptr
        };
        struct HksParam params[] = {
            {
                .tag = HKS_TAG_PARAM0_UINT32,
                .uint32Param = HKS_EVENT_SUBSCRIBE_SYSTEM_EVENT_FAIL
            },
            {
                .tag = HKS_TAG_PARAM0_BUFFER,
                .blob = { strlen(funcName) + 1, (uint8_t *)funcName }
            },
            {
                .tag = HKS_TAG_PARAM1_BUFFER,
                .blob = { sizeof(time), (uint8_t *)&time }
            },
            {
                .tag = HKS_TAG_PARAM3_BUFFER,
                .blob = { sizeof(resultInfo), (uint8_t *)&resultInfo }
            }
        };
        ret = HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "add params failed")

        ret = HksBuildParamSet(&reportParamSet);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "build paramset failed")

        HksEventReport(funcName, nullptr, nullptr, reportParamSet, errorCode);
    } while (0);

    HksFreeParamSet(&reportParamSet);
}
