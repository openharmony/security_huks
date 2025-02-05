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
#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_mem.h"

static int32_t AppendToNewParamSet(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *newParamSet = NULL;

    do {
        ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check paramSet failed")

        ret = HksFreshParamSet((struct HksParamSet *)paramSet, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append fresh paramset failed")

        ret = HksInitParamSet(&newParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append init operation param set failed")

        ret = HksAddParams(newParamSet, paramSet->params, paramSet->paramsCnt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "append params failed")

        *outParamSet = newParamSet;
        return ret;
    } while (0);

    HksFreeParamSet(&newParamSet);
    return ret;
}

void HksEventReport(const char *funcName, const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksParamSet *reportParamSet, int32_t errorCode)
{
    struct HksParam *eventParam = NULL;
    int32_t ret = HksGetParam(reportParamSet, HKS_TAG_PARAM0_UINT32, &eventParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Failed to get eventparam from reportParamSet");
        return;
    }

    uint32_t eventId = eventParam->uint32Param;
    HKS_LOG_I("eventId in HksEventReport is %" LOG_PUBLIC "u", eventId);

    struct HksParamSet *newParamSet = NULL;
    ret = AppendToNewParamSet(reportParamSet, &newParamSet);
    if (ret != HKS_SUCCESS) {
        return;
    }
    
    ret = HksBuildParamSet(&newParamSet);
    if (ret != HKS_SUCCESS) {
        return;
    }

    bool enqueueSuccess = HksHaPlugin::GetInstance().Enqueue(eventId, newParamSet);
    if (!enqueueSuccess) {
        HKS_LOG_E("Report fault event failed");
        HksFreeParamSet(&newParamSet);
    }
}