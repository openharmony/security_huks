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

#include "hks_report_common.h"

#include <cerrno>
#include <shared_mutex>
#include <cstdint>
#include <string>
#include <sys/stat.h>
#include "hilog/log_c.h"
#include "hks_error_code.h"
#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "hks_util.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
/*
HKS_TAG_PARAM0_UINT32 -> eventId
HKS_TAG_PARAM0_BUFFER -> function
HKS_TAG_PARAM1_UINT32 -> operation
HKS_TAG_PARAM1_BUFFER -> time
HKS_TAG_PARAM2_BUFFER -> processName
HKS_TAG_PARAM2_UINT32 -> processUid
HKS_TAG_PARAM3_BUFFER -> result
HKS_TAG_PARAM3_UINT32 -> timeCost
HKS_TAG_PARAM0_NULL -> errorMsg

HKS_TAG_PARAM1_NULL -> accessGroup
HKS_TAG_PARAM2_NULL -> developerId

HKS_TAG_PARAM4_UINT32 -> keyAliasHash
HKS_TAG_PARAM5_UINT32 -> keyHash
HKS_TAG_PARAM6_UINT32 -> renameDstKeyAliasHash
*/

void DeConstructReportParamSet(struct HksParamSet **paramSet)
{
    HksFreeParamSet(paramSet);
}

int32_t AddGroupKey(struct HksParamSet *paramSetOut, const struct HksParamSet *paramSetIn)
{
    struct HksParam *accessGroupParam{ nullptr };
    struct HksParam *developerIdParam{ nullptr };
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_KEY_ACCESS_GROUP, &accessGroupParam);
    HKS_IF_TRUE_RETURN(ret == HKS_ERROR_PARAM_NOT_EXIST, HKS_SUCCESS)
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get access group failed")

    ret = HksGetParam(paramSetIn, HKS_TAG_DEVELOPER_ID, &developerIdParam);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get developer id failed")

    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM1_NULL,
            .blob = accessGroupParam->blob
        }, {
            .tag = HKS_TAG_PARAM2_NULL,
            .blob = developerIdParam->blob
        }
    };

    ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Add group key info failed")

    return ret;
}

int32_t AddKeyHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyIn)
{
    uint16_t keyHash = static_cast<uint16_t>(HksGetHash(keyIn));
    struct HksParam keyParams[] = {
        {
            .tag = HKS_TAG_PARAM5_UINT32,
            .uint32Param = (uint32_t)keyHash
        }
    };
    int32_t ret = HksAddParams(paramSetOut, keyParams, HKS_ARRAY_SIZE(keyParams));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "AddKeyHash failed")
    return ret;
}

int32_t AddKeyAliasHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias, enum HksInnerTag paramTag)
{
    uint8_t keyAliasHash = static_cast<uint8_t>(HksGetHash(keyAlias));
    struct HksParam hashKeyAliasParam = {
        .tag = paramTag,
        .uint32Param = (uint32_t)keyAliasHash
    };
    int32_t ret = HksAddParams(paramSetOut, &hashKeyAliasParam, 1);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "AddKeyAliasHash failed")
    return ret;
}

static int32_t AddErrorMessage(struct HksParamSet *paramSetOut)
{
    const char *errMsg = HksGetThreadErrorMsg();
    HKS_IF_NULL_LOGI_RETURN(errMsg, HKS_ERROR_NULL_POINTER, "error msg is null")
    struct HksParam param = {
        .tag = HKS_TAG_PARAM0_NULL,
        .blob = { .size = strlen(errMsg) + 1, .data = (uint8_t*)errMsg },
    };
    int32_t ret = HksAddParams(paramSetOut, &param, 1);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Add error msg failed")
    return ret;
}

int32_t AddTimeCost(struct HksParamSet *paramSetOut, uint64_t startTime)
{
    uint64_t endTime = 0;
    (void)HksElapsedRealTime(&endTime);
    uint32_t totalCost = 0;
    if (endTime >= startTime) {
        totalCost = static_cast<uint32_t>(endTime - startTime);
    } else {
        HKS_LOG_I("startTime is bigger than endTime. diff time: %" LOG_PUBLIC "d",
            static_cast<uint32_t>(startTime - endTime));
    }
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM3_UINT32,
            .uint32Param = totalCost
        }
    };
    int32_t ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Add error msg failed")
    return ret;
}

int32_t PreAddCommonInfo(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, uint64_t startTime)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "paramSetIn is null ptr")

    int32_t ret = AddTimeCost(paramSetOut, startTime);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add time cost to paramSetOut failed!")

    ret = AddKeyAliasHash(paramSetOut, keyAlias, HKS_TAG_PARAM4_UINT32);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add kayAlias hash to paramSetOut failed!")

    ret = AddGroupKey(paramSetOut, paramSetIn);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add group params to paramSetOut failed!")

    ret = HksAddParams(paramSetOut, paramSetIn->params, paramSetIn->paramsCnt);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add paramSetIn params to paramSetOut failed!")

    return ret;
}

static int32_t AddProcessInfo(struct HksParamSet *paramSetOut, const struct HksProcessInfo *processInfo)
{
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM2_UINT32,
            .uint32Param = processInfo->uidInt,
        }
    };
    int32_t ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI(ret, "AddProcessInfo failed")
    return ret;
}

static int32_t AddFuncName(struct HksParamSet *paramSetOut, const char *funcName)
{
    struct HksParam params[]  = {
        {
            .tag = HKS_TAG_PARAM0_BUFFER,
            .blob = { .size = strlen(funcName) + 1, .data = (uint8_t*)funcName },
        }
    };
    int32_t ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI(ret, "AddFuncName failed")
    return ret;
}

static int32_t AddCommonInfo(const char *funcName, const struct HksProcessInfo *processInfo,
    struct HksParamSet *reportParamSet)
{
    int32_t ret = AddProcessInfo(reportParamSet, processInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add processInfo to params failed")

    ret = AddFuncName(reportParamSet, funcName);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add function name to params failed")

    ret = AddErrorMessage(reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add error message to params failed")
    return ret;
}

static enum HksCallerType HksGetCallerType(void)
{
    auto callingTokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    switch (OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callingTokenId)) {
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP:
            return HKS_HAP_TYPE;
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE:
        case OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL:
            return HKS_SA_TYPE;
        default:
            HKS_LOG_I("Error token type, callerTokenId: %" LOG_PUBLIC "u", callingTokenId);
            return HKS_UNIFIED_TYPE;
    }
}

int32_t ReportGetCallerName(std::string &callerName)
{
    auto callingTokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    switch (HksGetCallerType()) {
        case HKS_HAP_TYPE: {
            OHOS::Security::AccessToken::HapTokenInfo hapTokenInfo;
            int32_t accessTokenRet = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callingTokenId,
                hapTokenInfo);
            HKS_IF_TRUE_LOGI_RETURN(accessTokenRet != OHOS::Security::AccessToken::AccessTokenKitRet::RET_SUCCESS,
                HKS_ERROR_BAD_STATE, "GetHapTokenInfo failed, ret: %" LOG_PUBLIC "d", accessTokenRet)
            callerName = hapTokenInfo.bundleName;
            return HKS_SUCCESS;
        }
        case HKS_SA_TYPE: {
            OHOS::Security::AccessToken::NativeTokenInfo saTokenInfo;
            int32_t accessTokenRet = OHOS::Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(callingTokenId,
                saTokenInfo);
            HKS_IF_TRUE_LOGI_RETURN(accessTokenRet != OHOS::Security::AccessToken::AccessTokenKitRet::RET_SUCCESS,
                HKS_ERROR_BAD_STATE, "GetNativeTokenInfo failed, ret: %" LOG_PUBLIC "d", accessTokenRet)
            callerName = saTokenInfo.processName;
            return HKS_SUCCESS;
        }
        default: {
            HKS_LOG_I("Invalid caller Type!");
            return HKS_ERROR_BAD_STATE;
        }
    }
}

int32_t ConstructReportParamSet(const char *funcName, const struct HksProcessInfo *processInfo,
    int32_t errorCode, struct HksParamSet **reportParamSet)
{
    HKS_IF_TRUE_LOGI_RETURN(funcName == nullptr || processInfo == nullptr || reportParamSet == nullptr ||
        *reportParamSet == nullptr, HKS_ERROR_NULL_POINTER, "ConstructReportParamSet params is null")
    int32_t ret = AddCommonInfo(funcName, processInfo, *reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "ConstructReportParamSet add common info failed!")

    struct HksEventResultInfo resultInfo = {
        .code = errorCode,
        .module = 0,
        .stage = 0,
        .errMsg = nullptr
    };
    struct timespec time;
    (void)timespec_get(&time, TIME_UTC);
    std::string callerName = "Invalid caller name";
    ret = ReportGetCallerName(callerName);
    HKS_IF_NOT_SUCC_LOGI(ret, "ReportGetCallerName failed")
    struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM1_BUFFER,
            .blob = { .size = sizeof(time), .data = (uint8_t *)&time },
        },
        {
            .tag = HKS_TAG_PARAM3_BUFFER,
            .blob = { .size = sizeof(resultInfo), .data = (uint8_t *)&resultInfo },
        },
        {
            .tag = HKS_TAG_PARAM2_BUFFER,
            .blob = { .size = callerName.size() + 1, .data = (uint8_t *)callerName.c_str() },
        }
    };
    std::unique_ptr<struct HksParamSet *, decltype(&HksFreeParamSet)> commonParamSet(reportParamSet, HksFreeParamSet);
    ret = HksAddParams(*reportParamSet, params, HKS_ARRAY_SIZE(params));
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add params to reportParamSet failed")

    ret = HksBuildParamSet(reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Buil reportParamSet failed")

    (void)commonParamSet.release();
    return HKS_SUCCESS;
}

static int32_t GetCommonEventBuffer(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    int32_t ret = HKS_FAILURE;
    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        ret = CopyParamBlobData(&eventInfo->common.function, paramToEventInfo);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Copy function failed")
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM2_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        ret = CopyParamBlobData(&eventInfo->common.callerInfo.name, paramToEventInfo);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Copy caller name failed")
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_NULL, &paramToEventInfo) == HKS_SUCCESS) {
        ret = CopyParamBlobData(&eventInfo->common.result.errMsg, paramToEventInfo);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Copy errMsg failed")
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM1_NULL, &paramToEventInfo) == HKS_SUCCESS) {
        ret = CopyParamBlobData(&eventInfo->common.accessGroup, paramToEventInfo);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Copy accessGroup failed")
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM2_NULL, &paramToEventInfo) == HKS_SUCCESS) {
        ret = CopyParamBlobData(&eventInfo->common.developerId, paramToEventInfo);
        HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Copy developerId failed")
    }

    return HKS_SUCCESS;
}

int32_t GetCommonEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "GetCommonEventInfo paramSetIn is null")
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "GetCommonEventInfo eventInfo is null")

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.eventId = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM1_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.operation = paramToEventInfo->uint32Param;
    }

    eventInfo->common.count = 1;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM1_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        if (paramToEventInfo->blob.size == sizeof(struct timespec)) {
            eventInfo->common.time = *(struct timespec *)paramToEventInfo->blob.data;
        }
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM2_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.callerInfo.uid = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM3_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        if (paramToEventInfo->blob.size == sizeof(struct HksEventResultInfo)) {
            eventInfo->common.result = *(struct HksEventResultInfo *)paramToEventInfo->blob.data;
        }
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM3_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.statInfo.totalCost = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_TRACE_ID, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.traceId = paramToEventInfo->uint64Param;
    }

    return GetCommonEventBuffer(paramSetIn, eventInfo);
}

void FreeCommonEventInfo(struct HksEventInfo *eventInfo)
{
    HKS_FREE(eventInfo->common.function);
    HKS_FREE(eventInfo->common.callerInfo.name);
    HKS_FREE(eventInfo->common.result.errMsg);
    HKS_FREE(eventInfo->common.accessGroup);
    HKS_FREE(eventInfo->common.developerId);
}

static bool CheckKeyInfo(const HksEventKeyInfo *keyInfo1, const HksEventKeyInfo *keyInfo2)
{
    return (keyInfo1->alg == keyInfo2->alg) && (keyInfo1->aliasHash == keyInfo2->aliasHash);
}

// check eventId and caller name are equal
bool CheckEventCommon(const struct HksEventInfo *info1, const struct HksEventInfo *info2)
{
    HKS_IF_TRUE_RETURN(info1 == nullptr || info2 == nullptr, false)
    HKS_IF_TRUE_RETURN(info1->common.eventId != info2->common.eventId || info1->common.callerInfo.name == nullptr ||
        info2->common.callerInfo.name == nullptr, false)
    return strcmp(info1->common.callerInfo.name, info2->common.callerInfo.name) == 0;
}

bool CheckEventCommonAndKey(const struct HksEventInfo *info1, const struct HksEventInfo *info2)
{
    HKS_IF_NOT_TRUE_RETURN(CheckEventCommon(info1, info2), false)

    switch (info1->common.eventId) {
        case HKS_EVENT_DERIVE:
        case HKS_EVENT_AGREE:
            return CheckKeyInfo(&info1->agreeDeriveInfo.keyInfo, &info2->agreeDeriveInfo.keyInfo);
        case HKS_EVENT_GENERATE_KEY:
            return CheckKeyInfo(&info1->generateInfo.keyInfo, &info2->generateInfo.keyInfo);
        case HKS_EVENT_IMPORT_KEY:
            return CheckKeyInfo(&info1->importInfo.keyInfo, &info2->importInfo.keyInfo);
        default:
            return false;
    }
}

int32_t GetEventKeyInfo(const struct HksParamSet *paramSetIn, struct HksEventKeyInfo *keyInfo)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "GetEventKeyInfo paramSetIn is null")
    HKS_IF_NULL_LOGI_RETURN(keyInfo, HKS_ERROR_NULL_POINTER, "GetEventKeyInfo eventInfo is null")
    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->aliasHash = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_AUTH_STORAGE_LEVEL, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->storageLevel = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_SPECIFIC_USER_ID, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->specificUserId = paramToEventInfo->int32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_ALGORITHM, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->alg = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PURPOSE, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->purpose = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_KEY_SIZE, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->keySize = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_KEY_FLAG, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->keyFlag = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM5_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->keyHash = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_IS_BATCH_OPERATION, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->isBatch = paramToEventInfo->boolParam;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_BATCH_PURPOSE, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->batchPur = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_BATCH_OPERATION_TIMEOUT, &paramToEventInfo) == HKS_SUCCESS) {
        keyInfo->batchTimeOut = paramToEventInfo->uint32Param;
    }
    return HKS_SUCCESS;
}

int32_t GetEventKeyAccessInfo(const struct HksParamSet *paramSetIn, struct HksEventKeyAccessInfo *keyAccessInfo)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "GetEventKeyAccessInfo paramSetIn is null")
    HKS_IF_NULL_LOGI_RETURN(keyAccessInfo, HKS_ERROR_NULL_POINTER, "GetEventKeyAccessInfo eventInfo is null")
    struct HksParam *paramToEventInfo;
    if (HksGetParam(paramSetIn, HKS_TAG_USER_AUTH_TYPE, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->authType = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->accessType = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_CHALLENGE_TYPE, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->challengeType = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_CHALLENGE_POS, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->challengePos = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_AUTH_TIMEOUT, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->authTimeOut = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_KEY_AUTH_PURPOSE, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->authPurpose = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_FRONT_USER_ID, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->frontUserId = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_USER_AUTH_MODE, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->authMode = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_IS_DEVICE_PASSWORD_SET, &paramToEventInfo) == HKS_SUCCESS) {
        keyAccessInfo->needPwdSet = paramToEventInfo->boolParam;
    }
    return HKS_SUCCESS;
}

std::pair<std::unordered_map<std::string, std::string>::iterator, bool> EventInfoToMapKeyInfo(
    const struct HksEventKeyInfo *eventKeyInfo, std::unordered_map<std::string, std::string> &reportData)
{
    auto ret = reportData.insert_or_assign("alias_hash", std::to_string(eventKeyInfo->aliasHash));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert alias hash failed!");

    ret = reportData.insert_or_assign("storage_level", std::to_string(eventKeyInfo->storageLevel));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert storage level failed!");

    ret = reportData.insert_or_assign("specific_os_account_id", std::to_string(eventKeyInfo->specificUserId));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert specific_os_account_id failed!");

    ret = reportData.insert_or_assign("algorithm", std::to_string(eventKeyInfo->alg));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert algorithm failed!");

    ret = reportData.insert_or_assign("purpose", std::to_string(eventKeyInfo->purpose));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert purpose failed!");

    ret = reportData.insert_or_assign("key_size", std::to_string(eventKeyInfo->keySize));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert key_size failed!");

    ret = reportData.insert_or_assign("key_flag", std::to_string(eventKeyInfo->keyFlag));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert keyFlag failed!");

    ret = reportData.insert_or_assign("key_hash", std::to_string(eventKeyInfo->keyHash));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert key_hash failed!");

    ret = reportData.insert_or_assign("batch_operation", std::to_string(eventKeyInfo->isBatch));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert batch_operation failed!");

    ret = reportData.insert_or_assign("batch_purpose", std::to_string(eventKeyInfo->batchPur));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert batch_purpose failed!");

    ret = reportData.insert_or_assign("batch_timeout", std::to_string(eventKeyInfo->batchTimeOut));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert batch_timeout failed!");
    return ret;
}

std::pair<std::unordered_map<std::string, std::string>::iterator, bool> EventInfoToMapKeyAccessInfo(
    const struct HksEventKeyAccessInfo *eventKeyAccessInfo, std::unordered_map<std::string, std::string> &reportData)
{
    auto ret = reportData.insert_or_assign("auth_type", std::to_string(eventKeyAccessInfo->authType));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert auth_type failed!");

    ret = reportData.insert_or_assign("access_type", std::to_string(eventKeyAccessInfo->accessType));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert access_type failed!");

    ret = reportData.insert_or_assign("challenge_type", std::to_string(eventKeyAccessInfo->challengeType));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert challenge_type failed!");

    ret = reportData.insert_or_assign("challenge_pos", std::to_string(eventKeyAccessInfo->challengePos));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert challenge_pos failed!");

    ret = reportData.insert_or_assign("auth_timeout", std::to_string(eventKeyAccessInfo->authTimeOut));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert auth_timeout failed!");

    ret = reportData.insert_or_assign("auth_purpose", std::to_string(eventKeyAccessInfo->authPurpose));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert auth_purpose failed!");

    ret = reportData.insert_or_assign("front_os_account_id", std::to_string(eventKeyAccessInfo->frontUserId));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert front_os_account_id failed!");

    ret = reportData.insert_or_assign("auth_mode", std::to_string(eventKeyAccessInfo->authMode));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert auth_mode failed!");

    ret = reportData.insert_or_assign("need_pwd_set", std::to_string(eventKeyAccessInfo->needPwdSet));
    HKS_IF_NOT_TRUE_LOGI(ret.second, "reportData insert need_pwd_set failed!");
    return ret;
}

int32_t CopyParamBlobData(char **dst, const struct HksParam *param)
{
    HKS_IF_TRUE_LOGI_RETURN(dst == nullptr || param == nullptr, HKS_ERROR_NULL_POINTER, "has null pointer")
    HKS_IF_TRUE_LOGI_RETURN(GetTagType((enum HksTag)(param->tag)) != HKS_TAG_TYPE_BYTES, HKS_ERROR_INVALID_ARGUMENT,
        "param type is not buffer")
    HKS_IF_TRUE_LOGI_RETURN(CheckBlob(&(param->blob)) != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT,
        "param blob is invalid")
    *dst = static_cast<char *>(HksMalloc(param->blob.size + 1));
    if (*dst != nullptr) {
        (void)memset_s(*dst, param->blob.size + 1, 0, param->blob.size + 1);
        (void)memcpy_s(*dst, param->blob.size + 1, param->blob.data, param->blob.size);
        (*dst)[param->blob.size] = '\0';
        return HKS_SUCCESS;
    }
    return HKS_ERROR_MALLOC_FAIL;
}