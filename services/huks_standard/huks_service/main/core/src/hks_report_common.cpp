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
#include "hilog/log_c.h"
#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report.h"
#include "hks_report_generate_key.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_storage_utils.h"
#include "hks_type_inner.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "hks_api.h"
#include "hks_util.h"
#include <shared_mutex>
#include <cstdint>
#include <string>
#include <sys/stat.h>
#include <ctime>
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "hks_api.h"
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

HKS_TAG_PARAM4_UINT32 -> keyAliasHash
HKS_TAG_PARAM5_UINT32 -> keyHash
HKS_TAG_PARAM6_UINT32 -> renameDstKeyAliasHash
*/
#define KEY_HASH_OFFSET 8
#define KEY_HASH_HIGHT 2
#define KEY_HASH_LOW 1

static int32_t GetHash(const struct HksBlob *data, struct HksBlob *hash)
{
    struct HksParam hashParams[] = {
        {
            .tag = HKS_TAG_DIGEST,
            .uint32Param = HKS_DIGEST_SHA256
        }
    };
    struct HksParamSet *hashParamSet = nullptr;
    int32_t ret = HksInitParamSet(&hashParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "init paramset failed!")

    do {
        ret = HksAddParams(hashParamSet, hashParams, HKS_ARRAY_SIZE(hashParams));
        HKS_IF_NOT_SUCC_BREAK(ret, "add params failed!")

        ret = HksBuildParamSet(&hashParamSet);
        HKS_IF_NOT_SUCC_BREAK(ret, "GetHash HksBuildParamSet failed");

        ret = HksHash(hashParamSet, data, hash);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "hash fail")
    } while (0);

    HksFreeParamSet(&hashParamSet);
    return ret;
}


int32_t GetKeyAliasHash(const struct HksBlob *keyAlias, uint8_t *keyAliasHash)
{
    uint8_t hashData[HASH_SHA256_SIZE] = {0};
    struct HksBlob hash = { HASH_SHA256_SIZE, hashData };
    
    int32_t ret = GetHash(keyAlias,  &hash);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get keyAlias hash failed")

    *keyAliasHash = hash.data[hash.size - 1];
    return ret;
}

int32_t GetKeyHash(const struct HksBlob *key, uint16_t *keyHash)
{
    uint8_t hashData[HASH_SHA256_SIZE] = {0};
    struct HksBlob hash = { HASH_SHA256_SIZE, hashData };
    *(keyHash) = 0x00;
    *(keyHash) |= hash.data[hash.size - KEY_HASH_HIGHT] << KEY_HASH_OFFSET;
    *(keyHash) |= hash.data[hash.size - KEY_HASH_LOW];
    return HKS_SUCCESS;
}

int32_t AddKeyHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyIn)
{
    uint16_t keyHash = 0xFFFF;
    int32_t ret = GetKeyHash(keyIn, &keyHash);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "GetKeyHash Failed!!")
    struct HksParam keyParams[] = {
        {
            .tag = HKS_TAG_PARAM5_UINT32,
            .uint32Param = (uint32_t)keyHash
        }
    };
    ret = HksAddParams(paramSetOut, keyParams, HKS_ARRAY_SIZE(keyParams));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AddKeyHash failed");
    }
    return ret;
}

int32_t AddKeyAliasHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias, enum HksInnerTag paramTag)
{
    uint8_t keyAliasHash = 0xFF;
    int32_t ret = GetKeyAliasHash(keyAlias, &keyAliasHash);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "GetKeyAliasHash Failed!!")
    struct HksParam hashKeyAliasParam = {
        .tag = paramTag,
        .uint32Param = (uint32_t)keyAliasHash
    };
    ret = HksAddParams(paramSetOut, &hashKeyAliasParam, 1);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AddKeyAliasHash failed");
    }
    return ret;
}

static int32_t AddErrorMessage(struct HksParamSet *paramSetOut)
{
    const char *errMsg = HksGetThreadErrorMsg();
    struct HksParam param = {
        .tag = HKS_TAG_PARAM0_NULL,
        .blob.size = strlen(errMsg), .blob.data = (uint8_t*)errMsg,
    };
    int32_t ret = HksAddParams(paramSetOut, &param, 1);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("add error msg to paramSetOut failed");
    }
    return ret;
}

int32_t AddTimeCost(struct HksParamSet *paramSetOut, uint64_t startTime)
{
    uint64_t endTime = 0;
    (void)HksElapsedRealTime(&endTime);
    uint32_t totalCost = static_cast<uint32_t>(endTime - startTime);
    struct HksParam params[] = {
    {
        .tag = HKS_TAG_PARAM3_UINT32,
        .uint32Param = totalCost
        }
    };
    int32_t ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("add time cost to paramSetOut failed");
    }
    return ret;
}

int32_t PreAddCommonInfo(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, uint64_t startTime)
{
    int32_t ret = AddTimeCost(paramSetOut, startTime);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreAddCommonInfo add time cost to paramSetOut failed!")

    ret = AddKeyAliasHash(paramSetOut, keyAlias, HKS_TAG_PARAM4_UINT32);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreAddCommonInfo add kayAlias hash to paramSetOut failed!")

    ret = HksAddParams(paramSetOut, paramSetIn->params, paramSetIn->paramsCnt);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "PreAddCommonInfo add paramSetIn params to paramSetOut failed!")

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
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AddProcessInfo failed");
    }
    return ret;
}

static int32_t AddFuncName(struct HksParamSet *paramSetOut, const char *funcName)
{
    struct HksParam params[]  = {
        {
            .tag = HKS_TAG_PARAM0_BUFFER,
            .blob.size = strlen(funcName),
            .blob.data = (uint8_t*)funcName
        }
    };
    int32_t ret = HksAddParams(paramSetOut, params, HKS_ARRAY_SIZE(params));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("AddFuncName failed");
    }
    return ret;
}

static int32_t AddCommonInfo(const char *funcName, const struct HksProcessInfo *processInfo,
    int32_t errorCode, struct HksParamSet *reportParamSet)
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
            if (accessTokenRet != OHOS::Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
                HKS_LOG_I("GetHapTokenInfo failed, ret: %" LOG_PUBLIC "d", accessTokenRet);
                return HKS_ERROR_BAD_STATE;
            }
            callerName = hapTokenInfo.bundleName;
            return HKS_SUCCESS;
        }
        case HKS_SA_TYPE: {
            OHOS::Security::AccessToken::NativeTokenInfo saTokenInfo;
            int32_t accessTokenRet = OHOS::Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(callingTokenId,
                saTokenInfo);
            if (accessTokenRet != OHOS::Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
                HKS_LOG_I("GetNativeTokenInfo failed, ret: %" LOG_PUBLIC "d", accessTokenRet);
                return HKS_ERROR_BAD_STATE;
            }
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
    if (funcName == nullptr || processInfo == nullptr || reportParamSet == nullptr || *reportParamSet == nullptr) {
        HKS_LOG_I("ConstructReportParamSet params is null");
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = AddCommonInfo(funcName, processInfo, errorCode,  *reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "ConstructReportParamSet add common info failed!")

    do {
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
                .blob.size = sizeof(time), .blob.data = (uint8_t *)&time,
            },
            {
                .tag = HKS_TAG_PARAM3_BUFFER,
                .blob.size = sizeof(resultInfo), .blob.data = (uint8_t *)&resultInfo,
            },
            {
                .tag = HKS_TAG_PARAM2_BUFFER,
                .blob.size = callerName.size() + 1, .blob.data = (uint8_t *)callerName.data()
            }
        };
        ret = HksAddParams(*reportParamSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "add params to reportParamSet failed")

        ret = HksBuildParamSet(reportParamSet);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "Buil reportParamSet failed")
    } while (0);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("ConstructReportParamSet failed");
        HksFreeParamSet(reportParamSet);
    }
    return ret;
}

int32_t GetCommonEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGI_RETURN(paramSetIn, HKS_ERROR_NULL_POINTER, "GetCommonEventInfo paramSetIn is null")
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "GetCommonEventInfo eventInfo is null")

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.eventId = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.function = (char *)HksMalloc(paramToEventInfo->blob.size + 1);
        (void)memcpy_s(eventInfo->common.function, paramToEventInfo->blob.size + 1, paramToEventInfo->blob.data,
            paramToEventInfo->blob.size);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM1_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.operation = paramToEventInfo->uint32Param;
    }

    eventInfo->common.count = 1;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM1_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.time = *(struct timespec *)paramToEventInfo->blob.data;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM2_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.callerInfo.name = (char *)HksMalloc(paramToEventInfo->blob.size + 1);
        (void)memcpy_s(eventInfo->common.callerInfo.name, paramToEventInfo->blob.size + 1, paramToEventInfo->blob.data,
            paramToEventInfo->blob.size);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM2_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.callerInfo.uid = paramToEventInfo->uint32Param;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM3_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.result = *(struct HksEventResultInfo*)paramToEventInfo->blob.data;
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_NULL, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.result.errMsg = (char *)HksMalloc(paramToEventInfo->blob.size + 1);
        (void)memcpy_s(eventInfo->common.result.errMsg, paramToEventInfo->blob.size + 1, paramToEventInfo->blob.data,
            paramToEventInfo->blob.size);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM3_UINT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->common.statInfo.totalCost = paramToEventInfo->uint32Param;
    }
    return HKS_SUCCESS;
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
        keyInfo->specificUserId = paramToEventInfo->uint32Param;
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