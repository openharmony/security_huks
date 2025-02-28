/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hks_ha_event_report.h"
#include "hks_ha_plugin.h"
#include "hks_log.h"
#include "hks_report.h"
#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_client_service_common.h"

void HksEventReport(const char *funcName, const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksParamSet *reportParamSet, int32_t errorCode)
{
    struct HksParam *eventIdParam = nullptr;
    int32_t ret = HksGetParam(reportParamSet, HKS_TAG_PARAM0_UINT32, &eventIdParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(ret, "Failed to get eventIdParam from reportParamSet")

    uint32_t eventId = eventIdParam->uint32Param;
#ifdef HA_REPORT
    struct HksParamSet *newParamSet = nullptr;
    ret = AppendToNewParamSet(reportParamSet, &newParamSet);
    HKS_IF_NOT_SUCC_RETURN_VOID(ret)

    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&newParamSet);
        return;
    }
    bool enqueueSuccess = HksHaPlugin::GetInstance().Enqueue(eventId, newParamSet);
    if (!enqueueSuccess) {
        HKS_LOG_E("Report fault event failed");
        HksFreeParamSet(&newParamSet);
    }
#else
    if (eventId == HKS_EVENT_DELETE_KEY) {
        if (ret != HKS_ERROR_NOT_EXIST) {
            HksReport(__func__, processInfo, nullptr, ret);
        }
    } else {
        HksReport(funcName, processInfo, paramSet, errorCode);
    }
#endif
}