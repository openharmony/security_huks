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

#include "hks_report_rename_key.h"

#include <cstdint>
#include <string>
#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_report_common.h"

int32_t PreConstructRenameReportParamSet(const struct HksBlob *keyAlias, const struct HksBlob *dstKeyAlias,
    const struct HksParamSet *paramSetIn, uint64_t startTime, struct HksParamSet **paramSetOut)
{
    HKS_IF_TRUE_LOGI_RETURN(keyAlias == nullptr || paramSetIn == nullptr, HKS_ERROR_NULL_POINTER,
        "PreConstructRenameReportParamSet params is null")
    int32_t ret = HksInitParamSet(paramSetOut);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreConstructRenameReportParamSet InitParamSet failed")

    std::unique_ptr<struct HksParamSet *, decltype(&HksFreeParamSet)> renameParamSet(paramSetOut, HksFreeParamSet);
    ret = PreAddCommonInfo(*paramSetOut, keyAlias, paramSetIn, startTime);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "pre add common info to params failed!")

    ret = AddKeyAliasHash(*paramSetOut, dstKeyAlias, HKS_TAG_PARAM6_UINT32);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "pre add key dest alias hash to params failed!")

    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM1_UINT32,
            .uint32Param = HKS_EVENT_RENAME_KEY
        },
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_RENAME_KEY
        },
    };
    ret = HksAddParams(*paramSetOut, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add in params failed!")

    (void)renameParamSet.release();
    return HKS_SUCCESS;
}

int32_t HksParamSetToEventInfoForRename(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksParamSetToEventInfoForRename params is null")

    std::unique_ptr<struct HksEventInfo, decltype(&FreeCommonEventInfo)> commEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    ret = GetEventKeyInfo(paramSetIn, &(eventInfo->renameInfo.keyInfo));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetEventKeyInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM6_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->renameInfo.dstAliasHash = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_IS_COPY_NEW_KEY, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->renameInfo.isCopy = static_cast<uint32_t>(paramToEventInfo->boolParam);
    }

    (void)commEventInfo.release();
    return HKS_SUCCESS;
}

bool HksEventInfoIsNeedReportForRename(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksEventInfoIsEqualForRename(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return CheckEventCommon(eventInfo1, eventInfo2);
}

void HksEventInfoAddForRename(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksEventInfoIsEqualForRename(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksEventInfoToMapForRename(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "HksEventInfoToMapForRename evenInfo is null")
    auto ret = EventInfoToMapKeyInfo(&eventInfo->renameInfo.keyInfo, reportData);
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData EventInfoToMapKeyInfo failed!");

    ret = reportData.insert_or_assign("dst_alias_hash", std::to_string(eventInfo->renameInfo.dstAliasHash));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert agree_pubkey_is_alias failed!");

    ret = reportData.insert_or_assign("copy_key", std::to_string(eventInfo->renameInfo.isCopy));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert agree_pubkey_is_alias failed!");

    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL,
        "HksEventInfoToMapForImport failed! reportData insert failed!")
    return HKS_SUCCESS;
}