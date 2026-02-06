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

#include "hks_report_data_size.h"

#include <cstdint>
#include <string>
#include "hks_event_info.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_report_common.h"
#include "hks_file_operator.h"
#include "hks_ha_event_report.h"
#include "hks_mem.h"
#include "hks_util.h"
#include "securec.h"
#include "directory_ex.h"

constexpr static char COMPONENT_NAME[] = "HUKS";
constexpr static char PARTITION_NAME[] = "/data";
constexpr static char FUNCTION_NAME[] = "ReportDataSizeEvent";

static int32_t AddDataSizeParam(
    const std::string &foldSize, const std::string &foldPath, struct HksParamSet **reportParamSet)
{
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_DATA_SIZE_STATISTICS
        },
        {
            .tag = HKS_TAG_COMPONENT_NAME,
            .blob = { strlen(COMPONENT_NAME) + 1, (uint8_t *)COMPONENT_NAME }
        },
        {
            .tag = HKS_TAG_PARTITION_NAME,
            .blob = { strlen(PARTITION_NAME) + 1, (uint8_t *)PARTITION_NAME }
        },
        {
            .tag = HKS_TAG_REMAIN_PARTITION_SIZE,
            .uint64Param = static_cast<uint64_t>(GetDeviceValidSize(PARTITION_NAME))
        },
        {
            .tag = HKS_TAG_FILE_OF_FOLDER_PATH,
            .blob = { foldPath.size() + 1, (uint8_t *)(foldPath.c_str()) }
        },
        {
            .tag = HKS_TAG_FILE_OF_FOLDER_SIZE,
            .blob = { foldSize.size() + 1, (uint8_t *)(foldSize.c_str()) }
        },
        {
            .tag = HKS_TAG_PARAM2_BUFFER,
            .blob = { strlen(COMPONENT_NAME) + 1, (uint8_t *)COMPONENT_NAME }
        },
        {
            .tag = HKS_TAG_PARAM0_BUFFER,
            .blob = { strlen(FUNCTION_NAME) + 1, (uint8_t *)FUNCTION_NAME }
        }
    };
    int32_t ret = HksAddParams(*reportParamSet, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add params failed");
    return HKS_SUCCESS;
}

int32_t PreConstructDataSizeReportParamSet(int userId, struct HksParamSet **reportParamSet)
{
    int32_t ret = HksInitParamSet(reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "init report paramset fail");
    std::string userStr = "/" + std::to_string(userId);
    std::string el1Path = HKS_EL1_DATA_PATH;
    std::string el2Path = HKS_EL2_DATA_PATH + userStr + HKS_DIRECTOREY_NAME;
    std::string el4Path = HKS_EL4_DATA_PATH + userStr + HKS_DIRECTOREY_NAME;
    uint64_t startTime = 0;
    (void)HksElapsedRealTime(&startTime);
    std::string foldSize = "[" +
        std::to_string(OHOS::GetFolderSize(el1Path)) + ", " +
        std::to_string(OHOS::GetFolderSize(el2Path)) + ", " +
        std::to_string(OHOS::GetFolderSize(el4Path)) + "]";
    std::string foldPath = "[\"" + el1Path + "\", \"" + el2Path + "\", \"" + el4Path + "\"]";
    std::unique_ptr<struct HksParamSet *, decltype(&HksFreeParamSet)> dataSizeParamSet(reportParamSet, HksFreeParamSet);
    ret = AddTimeCost(*reportParamSet, startTime);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add time cost to reportParamSet failed!")

    ret = AddDataSizeParam(foldSize, foldPath, reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "AddDataSizeParam failed");

    ret = HksBuildParamSet(reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "build paramset failed");

    (void)dataSizeParamSet.release();
    return HKS_SUCCESS;
}

int32_t HksParamSetToEventInfoForDataSize(const struct HksParamSet *paramSetIn, struct HksEventInfo* eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER, "params is null")

    std::unique_ptr<struct HksEventInfo, decltype(&FreeCommonEventInfo)> commEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_COMPONENT_NAME, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->dataSizeInfo.component = reinterpret_cast<char *>(paramToEventInfo->blob.data);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARTITION_NAME, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->dataSizeInfo.partition = reinterpret_cast<char *>(paramToEventInfo->blob.data);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_FILE_OF_FOLDER_PATH, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->dataSizeInfo.foldPath = reinterpret_cast<char *>(paramToEventInfo->blob.data);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_FILE_OF_FOLDER_SIZE, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->dataSizeInfo.foldSize = reinterpret_cast<char *>(paramToEventInfo->blob.data);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_REMAIN_PARTITION_SIZE, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->dataSizeInfo.partitionRemain = paramToEventInfo->uint64Param;
    }

    (void)commEventInfo.release();
    return HKS_SUCCESS;
}

bool HksEventInfoIsNeedReportForDataSize([[maybe_unused]] const struct HksEventInfo *eventInfo)
{
    return true;
}

bool HksEventInfoIsEqualForDataSize([[maybe_unused]] const struct HksEventInfo *eventInfo1,
    [[maybe_unused]] const struct HksEventInfo *eventInfo2)
{
    /* data size event is not a statistic event */
    return false;
}

void HksEventInfoAddForDataSize(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksEventInfoIsEqualForDataSize(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksEventInfoToMapForDataSize(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "HksEventInfoToMapForDataSize evenInfo is null")

    const char *component = (eventInfo->dataSizeInfo.component != nullptr) ?
        eventInfo->dataSizeInfo.component : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("componentName", std::string(component));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert component failed!");

    const char *partition = (eventInfo->dataSizeInfo.partition != nullptr) ?
        eventInfo->dataSizeInfo.partition : EVENT_PROPERTY_UNKNOWN;
    ret = reportData.insert_or_assign("partitionName", std::string(partition));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert partition failed!");

    const char *foldPath = (eventInfo->dataSizeInfo.foldPath != nullptr) ?
        eventInfo->dataSizeInfo.foldPath : EVENT_PROPERTY_UNKNOWN;
    ret = reportData.insert_or_assign("filepath", std::string(foldPath));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert foldPath failed!");

    const char *foldSize = (eventInfo->dataSizeInfo.foldSize != nullptr) ?
        eventInfo->dataSizeInfo.foldSize : EVENT_PROPERTY_UNKNOWN;
    ret = reportData.insert_or_assign("filesize", std::string(foldSize));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert foldSize failed!");

    ret = reportData.insert_or_assign("remainPartitionSize", std::to_string(eventInfo->dataSizeInfo.partitionRemain));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert partitionRemain failed!");

    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL,
        "HksEventInfoToMapForDataSize failed! reportData insert failed!")
    return HKS_SUCCESS;
}

void ReportDataSizeEvent(int userId)
{
    HksParamSet *reportParamSet = { nullptr };
    int32_t ret = PreConstructDataSizeReportParamSet(userId, &reportParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("PreConstructDataSizeReportParamSet failed");
        HksFreeParamSet(&reportParamSet);
        return;
    }
    HksEventReport(__func__, nullptr, nullptr, reportParamSet, HKS_SUCCESS);
    HksFreeParamSet(&reportParamSet);
}