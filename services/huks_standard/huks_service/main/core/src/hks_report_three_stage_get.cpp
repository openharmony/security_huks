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

#include "hks_report_three_stage_get.h"

#include <cstdint>
#include <ctime>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include "securec.h"

#include "hks_error_msg.h"
#include "hks_event_info.h"
#include "hks_mem.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_report_common.h"
#include "hks_session_manager.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_util.h"
#include "hks_ha_event_report.h"

static uint32_t g_threeStageEvent[] = {
    HKS_EVENT_CRYPTO,
    HKS_EVENT_SIGN_VERIFY,
    HKS_EVENT_DERIVE,
    HKS_EVENT_AGREE,
    HKS_EVENT_MAC,
};

static uint32_t g_threeStage[] = {
    HKS_INIT,
    HKS_UPDATE,
    HKS_FINISH,
    HKS_ABORT,
};

static std::unordered_map<enum HksReportStage, enum HksEventId> g_eventIdMap = {
    { HKS_ONE_STAGE_CRYPTO, HKS_EVENT_CRYPTO },
    { HKS_ONE_STAGE_SIGN_VERIFY, HKS_EVENT_SIGN_VERIFY },
    { HKS_ONE_STAGE_DERIVE, HKS_EVENT_DERIVE },
    { HKS_ONE_STAGE_AGREE, HKS_EVENT_AGREE },
    { HKS_ONE_STAGE_MAC, HKS_EVENT_MAC },
    { HKS_ONE_STAGE_ATTEST, HKS_EVENT_ATTEST }
};

static int32_t GetOneStageEventId(enum HksReportStage stage, HksEventInfo *eventInfo)
{
    if (g_eventIdMap.count(stage) == 0) {
        return HKS_FAILURE;
    }
    eventInfo->common.eventId = static_cast<uint32_t>(g_eventIdMap[stage]);
    return HKS_SUCCESS;
}

static int32_t GetEventId(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null");

    struct HksParam *purposeParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &purposeParam);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get purpose param fail")
    eventInfo->common.operation = purposeParam->uint32Param;

    switch (purposeParam->uint32Param) {
        case HKS_KEY_PURPOSE_ENCRYPT:
        case HKS_KEY_PURPOSE_DECRYPT:
            eventInfo->common.eventId = HKS_EVENT_CRYPTO;
            eventInfo->cryptoInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_SIGN:
        case HKS_KEY_PURPOSE_VERIFY:
            eventInfo->common.eventId = HKS_EVENT_SIGN_VERIFY;
            eventInfo->cryptoInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_DERIVE:
            eventInfo->common.eventId = HKS_EVENT_DERIVE;
            eventInfo->agreeDeriveInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_AGREE:
            eventInfo->common.eventId = HKS_EVENT_AGREE;
            eventInfo->agreeDeriveInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_MAC:
            eventInfo->common.eventId = HKS_EVENT_MAC;
            eventInfo->macInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        default:
            HKS_LOG_I("purpose no need report");
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

static void GetKeyAccessInfo(const struct HksParamSet *paramSet, HksEventKeyAccessInfo *info)
{
    struct HksParam *param = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_USER_AUTH_TYPE, &param);
    HKS_IF_NOT_SUCC_RETURN_VOID(ret)
    info->authType = param->uint32Param;

    if (HksGetParam(paramSet, HKS_TAG_KEY_AUTH_ACCESS_TYPE, &param) == HKS_SUCCESS) {
        info->accessType = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_CHALLENGE_TYPE, &param) == HKS_SUCCESS) {
        info->challengeType = param->uint32Param;
    }
    
    if (HksGetParam(paramSet, HKS_TAG_AUTH_TIMEOUT, &param) == HKS_SUCCESS) {
        info->authTimeOut = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_KEY_AUTH_PURPOSE, &param) == HKS_SUCCESS) {
        info->authPurpose = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_FRONT_USER_ID, &param) == HKS_SUCCESS) {
        info->frontUserId = (uint32_t)param->int32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_USER_AUTH_MODE, &param) == HKS_SUCCESS) {
        info->authMode = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_IS_DEVICE_PASSWORD_SET, &param) == HKS_SUCCESS) {
        info->needPwdSet = (uint32_t)param->boolParam;
    }
}

static void GetKeyInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    const struct HksBlob *key, HksEventKeyInfo *keyInfo)
{
    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &param) == HKS_SUCCESS) {
        keyInfo->storageLevel = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &param) == HKS_SUCCESS) {
        keyInfo->specificUserId = param->int32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_ALGORITHM, &param) == HKS_SUCCESS) {
        keyInfo->alg = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_KEY_SIZE, &param) == HKS_SUCCESS) {
        keyInfo->keySize = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_KEY_FLAG, &param) == HKS_SUCCESS) {
        keyInfo->keyFlag = param->uint32Param;
    }

    if (keyAlias != nullptr) {
        keyInfo->aliasHash = static_cast<uint8_t>(HksGetHash(keyAlias));
    }

    if (key != nullptr) {
        keyInfo->keyHash = static_cast<uint16_t>(HksGetHash(key));
    }
}

static void GetCryptoInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    const struct HksBlob *key, HksEventCryptoInfo *cryptoInfo)
{
    HKS_IF_NULL_RETURN_VOID(paramSet)
    GetKeyInfo(paramSet, keyAlias, key, &cryptoInfo->keyInfo);
    GetKeyAccessInfo(paramSet, &cryptoInfo->accessCtlInfo);

    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_BLOCK_MODE, &param) == HKS_SUCCESS) {
        cryptoInfo->blockMode = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_PADDING, &param) == HKS_SUCCESS) {
        cryptoInfo->padding = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_DIGEST, &param) == HKS_SUCCESS) {
        cryptoInfo->digest = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_MGF_DIGEST, &param) == HKS_SUCCESS) {
        cryptoInfo->mgfDigest = param->uint32Param;
    }
}

static void GetAgreeDeriveInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    const struct HksBlob *key, HksEventAgreeDeriveInfo *info)
{
    HKS_IF_NULL_RETURN_VOID(paramSet)
    GetKeyInfo(paramSet, keyAlias, key, &info->keyInfo);
    GetKeyAccessInfo(paramSet, &info->accessCtlInfo);

    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_ITERATION, &param) == HKS_SUCCESS) {
        info->iterCnt = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_DERIVE_AGREE_KEY_STORAGE_FLAG, &param) == HKS_SUCCESS) {
        info->storageFlag = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_DERIVE_KEY_SIZE, &param) == HKS_SUCCESS) {
        info->keySize = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_AGREE_PUBKEY_TYPE, &param) == HKS_SUCCESS) {
        info->pubKeyType = param->uint32Param;
    }
}

static void GetMacInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    const struct HksBlob *key, HksEventMacInfo *macInfo)
{
    HKS_IF_NULL_RETURN_VOID(paramSet)
    GetKeyInfo(paramSet, keyAlias, key, &macInfo->keyInfo);
    GetKeyAccessInfo(paramSet, &macInfo->accessCtlInfo);
}

static void GetAttestInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    const struct HksBlob *key, HksEventAttestInfo *attestInfo)
{
    HKS_IF_NULL_RETURN_VOID(paramSet)
    GetKeyInfo(paramSet, keyAlias, key, &attestInfo->keyInfo);

    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_CERT_TYPE, &param) == HKS_SUCCESS) {
        attestInfo->baseCertType = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_MODE, &param) == HKS_SUCCESS) {
        attestInfo->isAnonymous = param->uint32Param;
    }
}

static void FreshEventInfo(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    switch (eventInfo->common.eventId) {
        case HKS_EVENT_CRYPTO:
        case HKS_EVENT_SIGN_VERIFY:
            GetCryptoInfo(paramSet, nullptr, nullptr, &eventInfo->cryptoInfo);
            break;
        case HKS_EVENT_DERIVE:
        case HKS_EVENT_AGREE:
            GetAgreeDeriveInfo(paramSet, nullptr, nullptr, &eventInfo->agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, nullptr, nullptr, &eventInfo->macInfo);
            break;
        default:
            HKS_LOG_I("event id no need report!");
    }
}

static void FreshStatInfo(HksEventStatInfo *statInfo, uint32_t dataSize, enum HksReportStage stage, uint64_t startTime)
{
    if (!IsAdditionOverflow(statInfo->dataLen, dataSize)) {
        statInfo->dataLen += dataSize;
    }

    uint64_t endTime = 0;
    (void)HksElapsedRealTime(&endTime);
    uint32_t cost = 0;
    if (endTime >= startTime) {
        cost = static_cast<uint32_t>(endTime - startTime);
    }

    if (!IsAdditionOverflow(statInfo->totalCost, cost)) {
        statInfo->totalCost += cost;
    }

    switch (stage) {
        case HKS_INIT:
            statInfo->initCost = cost;
            break;
        case HKS_UPDATE:
            if (!IsAdditionOverflow(statInfo->updateCost, cost)) {
                statInfo->updateCost += cost;
            }
            statInfo->updateCount++;
            break;
        case HKS_FINISH:
            statInfo->finishCost = cost;
            break;
        case HKS_ABORT:
            break;
        default:
            break;
    }
}

static bool IsThreeStage(uint32_t stage)
{
    for (uint32_t id : g_threeStage) {
        if (id == stage) {
            return true;
        }
    }
    return false;
}

static int32_t CopyFirstErrorMsg(struct HksBlob *blob, const char *errorMsg, uint32_t errorMsgLen)
{
    blob->data = static_cast<uint8_t *>(HksMalloc(errorMsgLen));
    HKS_IF_NULL_LOGE_RETURN(blob->data, HKS_ERROR_MALLOC_FAIL, "CopyFirstErrorMsg: malloc fail")

    blob->size = errorMsgLen;

    if (memcpy_s(blob->data, blob->size, errorMsg, errorMsgLen) != EOK) {
        HKS_LOG_E("CopyFirstErrorMsg: memcpy_s fail");
        HKS_FREE_BLOB(*blob);
        return HKS_ERROR_INTERNAL_ERROR;
    }

    return HKS_SUCCESS;
}

static int32_t AppendErrorMsg(struct HksBlob *blob, const char *errorMsg, uint32_t errorMsgLen)
{
    uint32_t oldSize = blob->size;
    uint8_t *oldData = blob->data;
    uint32_t totalLen = oldSize + errorMsgLen - 1;
    uint8_t *newData = static_cast<uint8_t *>(HksMalloc(totalLen));
    HKS_IF_NULL_LOGE_RETURN(newData, HKS_ERROR_MALLOC_FAIL, "AppendErrorMsg: malloc fail")

    if (oldSize > 1) {
        if (memcpy_s(newData, totalLen, oldData, oldSize - 1) != EOK) {
            HKS_LOG_E("AppendErrorMsg: memcpy_s fail for oldData");
            HKS_FREE(newData);
            return HKS_ERROR_INTERNAL_ERROR;
        }
    }

    uint32_t offset = (oldSize > 1) ? (oldSize - 1) : 0;
    if (memcpy_s(newData + offset, totalLen - offset, errorMsg, errorMsgLen) != EOK) {
        HKS_LOG_E("AppendErrorMsg: memcpy_s fail for errorMsg");
        HKS_FREE(newData);
        return HKS_ERROR_INTERNAL_ERROR;
    }

    HKS_FREE_BLOB(*blob);
    blob->data = newData;
    blob->size = totalLen;
    HKS_LOG_I("blob->data in AppendErrorMsg content: %" LOG_PUBLIC "s", blob->data);

    return HKS_SUCCESS;
}

static int32_t CopyErrorMsgToBlob(struct HksBlob *blob, const char *errorMsg)
{
    HKS_IF_NULL_LOGE_RETURN(blob, HKS_ERROR_NULL_POINTER, "CopyErrorMsgToBlob: blob is null")
    HKS_IF_NULL_LOGE_RETURN(errorMsg, HKS_ERROR_NULL_POINTER, "CopyErrorMsgToBlob: errorMsg is null")

    uint32_t errorMsgLen = strlen(errorMsg) + 1;

    if (blob->data == NULL) {
        return CopyFirstErrorMsg(blob, errorMsg, errorMsgLen);
    } else {
        return AppendErrorMsg(blob, errorMsg, errorMsgLen);
    }
}

static int32_t HandleSuccessStage(const struct HksProcessInfo *processInfo, const HksThreeStageReportInfo *info,
    struct HksOperation *operation)
{
    HKS_IF_NULL_LOGI_RETURN(operation, HKS_ERROR_NOT_EXIST, "operation is not exist or busy in init report")
    return CopyErrorMsgToBlob(&operation->errMsgBlob, HksGetThreadErrorMsg());
}

static uint32_t CalculateTimeDifferenceMs(uint64_t startTimeMs, uint64_t curTimeMs)
{
    return static_cast<uint32_t>(curTimeMs - startTimeMs);
}

static int32_t HandleThreeStageOperation(const struct HksProcessInfo *processInfo, const HksThreeStageReportInfo *info,
    HksEventInfo *eventInfo, struct HksBlob *errMsg)
{
    HKS_IF_NULL_LOGI_RETURN(info->operation, HKS_ERROR_NOT_EXIST, "operation is null")
    HKS_IF_NOT_SUCC_RETURN(CheckBlob(&(info->operation->errMsgBlob)), HKS_ERROR_INVALID_ARGUMENT)

    errMsg->size = info->operation->errMsgBlob.size;
    errMsg->data = static_cast<uint8_t *>(HksMalloc(errMsg->size));
    if (errMsg->data == nullptr) {
        errMsg->size = 0;
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (memcpy_s(errMsg->data, errMsg->size, info->operation->errMsgBlob.data,
        info->operation->errMsgBlob.size) != EOK) {
        HKS_LOG_E("memcpy_s fail");
        HKS_FREE(errMsg->data);
        return HKS_ERROR_INTERNAL_ERROR;
    }

    uint64_t curTime = 0;
    (void)HksElapsedRealTime(&curTime);
    eventInfo->common.statInfo.saCost = CalculateTimeDifferenceMs(info->operation->startTime, curTime);

    return HKS_SUCCESS;
}

static int32_t GetErrorMessageData(const struct HksProcessInfo *processInfo, const HksThreeStageReportInfo *info,
    HksEventInfo *eventInfo, struct HksBlob *errMsg)
{
    if (IsThreeStage(info->stage)) {
        return HandleThreeStageOperation(processInfo, info, eventInfo, errMsg);
    }

    const char *errorMsg = HksGetThreadErrorMsg();
    HKS_IF_NULL_LOGI_RETURN(errorMsg, HKS_ERROR_NULL_POINTER, "get error msg fail")
    errMsg->data = reinterpret_cast<uint8_t *>(const_cast<char*>(errorMsg));
    errMsg->size = strlen(errorMsg) + 1;
    return HKS_SUCCESS;
}

static int32_t HksFreshAndReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, HksEventInfo *eventInfo)
{
    if (IsThreeStage(info->stage)) {
        FreshEventInfo(paramSet, eventInfo);
    }
    FreshStatInfo(&(eventInfo->common.statInfo), info->inDataSize, info->stage, info->startTime);

    if (info->errCode == HKS_SUCCESS && (info->stage == HKS_INIT || info->stage == HKS_UPDATE)) {
        return HandleSuccessStage(processInfo, info, info->operation);
    }

    struct timespec curTime;
    (void)timespec_get(&curTime, TIME_UTC);

    struct HksBlob errMsg = {0};
    struct HksParamSet *reportParamSet = nullptr;
    int32_t ret = HKS_SUCCESS;
    do {
        ret = GetErrorMessageData(processInfo, info, eventInfo, &errMsg);
        HKS_IF_NOT_SUCC_BREAK(ret);

        ret = HksInitParamSet(&reportParamSet);
        HKS_IF_NOT_SUCC_BREAK(ret);

        HksEventResultInfo result = { .code = info->errCode, .module = 0, .stage = 0, .errMsg = nullptr };
        eventInfo->common.result = result;
        std::string callerName;
        ret = ReportGetCallerName(callerName);
        const struct HksParam params[] = {
            { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = eventInfo->common.eventId },
            { .tag = HKS_TAG_PARAM0_BUFFER, .blob = { strlen(funcName) + 1, (uint8_t *)funcName } },
            { .tag = HKS_TAG_PARAM1_BUFFER, .blob = { sizeof(struct timespec), (uint8_t *)&curTime } },
            { .tag = HKS_TAG_PARAM2_BUFFER, .blob = { callerName.size() + 1, (uint8_t *)callerName.c_str() } },
            { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { sizeof(HksEventInfo), (uint8_t *)eventInfo } },
            { .tag = HKS_TAG_PARAM0_NULL, .blob = { errMsg.size, (uint8_t *)errMsg.data } },
            { .tag = HKS_TAG_TRACE_ID, .uint64Param = info->traceId },
        };

        ret = HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "add params fail")

        ret = HksBuildParamSet(&reportParamSet);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "build paramset fail")

        HKS_LOG_I("three stage report %" LOG_PUBLIC "s, purpose = %" LOG_PUBLIC "d, eventId = %" LOG_PUBLIC "d",
            funcName, eventInfo->common.operation, eventInfo->common.eventId);
        HksEventReport(funcName, processInfo, paramSet, reportParamSet, info->errCode);
    } while (0);

    HksFreeParamSet(&reportParamSet);
    if (IsThreeStage(info->stage)) {
        HKS_FREE(errMsg.data);
    }
    return ret;
}

int32_t HksOneStageEventReport(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksOneStageReportInfo *info)
{
    HKS_IF_TRUE_LOGI_RETURN(keyAlias == nullptr || paramSet == nullptr || processInfo == nullptr || info == nullptr,
        HKS_ERROR_NULL_POINTER, "keyAlias or paramset or processInfo or info is null")

    HksEventInfo eventInfo = {};
    int32_t ret = GetOneStageEventId(info->stage, &eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get one stage event id fail")

    eventInfo.common.callerInfo.uid = processInfo->uidInt;

    struct HksParam *purposeParam = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_PURPOSE, &purposeParam) == HKS_SUCCESS) {
        eventInfo.common.operation = purposeParam->uint32Param;
    }

    struct HksParamSet *keyBlobParamSet = nullptr;
    if (key != nullptr && key->data != nullptr && key->size >= sizeof(struct HksParamSet)) {
        keyBlobParamSet = reinterpret_cast<struct HksParamSet *>(key->data);
    }

    switch (eventInfo.common.eventId) {
        case HKS_EVENT_CRYPTO:
        case HKS_EVENT_SIGN_VERIFY:
            GetCryptoInfo(paramSet, keyAlias, key, &eventInfo.cryptoInfo);
            GetCryptoInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo.cryptoInfo);
            break;
        case HKS_EVENT_DERIVE:
        case HKS_EVENT_AGREE:
            GetAgreeDeriveInfo(paramSet, keyAlias, key, &eventInfo.agreeDeriveInfo);
            GetAgreeDeriveInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo.agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, keyAlias, key, &eventInfo.macInfo);
            GetMacInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo.macInfo);
            break;
        case HKS_EVENT_ATTEST:
            GetAttestInfo(paramSet, keyAlias, key, &(eventInfo.attestInfo));
            GetAttestInfo(keyBlobParamSet, nullptr, nullptr, &(eventInfo.attestInfo));
            break;
        default:
            HKS_LOG_I("event id no need report");
            return HKS_ERROR_NOT_SUPPORTED;
    }

    HksThreeStageReportInfo reportInfo = { info->errCode, 0, HKS_ONE_STAGE, info->startTime, 0, nullptr };
    (void)HksFreshAndReport(info->funcName, processInfo, paramSet, &reportInfo, &eventInfo);
    return HKS_SUCCESS;
}

int32_t HksGetInitEventInfo(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(keyAlias == nullptr || paramSet == nullptr || processInfo == nullptr ||
        eventInfo == nullptr, HKS_ERROR_NULL_POINTER, "keyAlias or paramset or processInfo or eventInfo is null")

    int32_t ret = GetEventId(paramSet, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get event id fail")
    eventInfo->common.callerInfo.uid = processInfo->uidInt;

    struct HksParamSet *keyBlobParamSet = nullptr;
    if (key != nullptr && key->data != nullptr && key->size >= sizeof(struct HksParamSet)) {
        keyBlobParamSet = reinterpret_cast<struct HksParamSet *>(key->data);
    }

    switch (eventInfo->common.eventId) {
        case HKS_EVENT_CRYPTO:
        case HKS_EVENT_SIGN_VERIFY:
            GetCryptoInfo(paramSet, keyAlias, key, &eventInfo->cryptoInfo);
            GetCryptoInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo->cryptoInfo);
            break;
        case HKS_EVENT_DERIVE:
        case HKS_EVENT_AGREE:
            GetAgreeDeriveInfo(paramSet, keyAlias, key, &eventInfo->agreeDeriveInfo);
            GetAgreeDeriveInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo->agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, keyAlias, key, &eventInfo->macInfo);
            GetMacInfo(keyBlobParamSet, nullptr, nullptr, &eventInfo->macInfo);
            break;
        default:
            HKS_LOG_I("event id no need report");
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

int32_t HksServiceInitReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSet == nullptr || info == nullptr || processInfo == nullptr || eventInfo == nullptr,
        HKS_ERROR_NULL_POINTER, "paramset or info or processInfo or eventInfo is null")

    if (info->errCode == HKS_SUCCESS) {
        struct HksOperation *operation = QueryOperationAndMarkInUse(processInfo, info->handle);
        HKS_IF_NULL_LOGI_RETURN(operation, HKS_ERROR_NOT_EXIST, "operation is not exist or busy in init report")

        operation->eventInfo = *eventInfo;
        operation->startTime = info->startTime;
        FreshStatInfo(&(eventInfo->common.statInfo), info->inDataSize, info->stage, info->startTime);
        int32_t ret = CopyErrorMsgToBlob(&operation->errMsgBlob, HksGetThreadErrorMsg());
        MarkOperationUnUse(operation);
        return ret;
    }
    HksFreshAndReport(funcName, processInfo, paramSet, info, eventInfo);
    return HKS_SUCCESS;
}

static bool IsThreeStageEvent(uint32_t eventId)
{
    for (uint32_t id : g_threeStageEvent) {
        if (id == eventId) {
            return true;
        }
    }
    return false;
}

int32_t HksThreeStageReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSet == nullptr || info == nullptr || processInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "paramset or info or processInfo is null")

    struct HksOperation *operation = info->operation;
    if (operation != nullptr) {
        uint32_t eventId = operation->eventInfo.common.eventId;
        HKS_IF_TRUE_LOGI_RETURN(!IsThreeStageEvent(eventId), HKS_FAILURE, "eventid is not support")

        if (info->errCode == HKS_SUCCESS && (info->stage == HKS_INIT || info->stage == HKS_UPDATE)) {
            return HandleSuccessStage(processInfo, info, operation);
        }

        (void)HksFreshAndReport(funcName, processInfo, paramSet, info, &operation->eventInfo);
        return HKS_SUCCESS;
    }

    HksEventInfo eventInfo {};
    int32_t ret = GetEventId(paramSet, &eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "get event id fail")
    eventInfo.common.callerInfo.uid = processInfo->uidInt;

    switch (eventInfo.common.eventId) {
        case HKS_EVENT_CRYPTO:
        case HKS_EVENT_SIGN_VERIFY:
            GetCryptoInfo(paramSet, nullptr, nullptr, &eventInfo.cryptoInfo);
            break;
        case HKS_EVENT_DERIVE:
        case HKS_EVENT_AGREE:
            GetAgreeDeriveInfo(paramSet, nullptr, nullptr, &eventInfo.agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, nullptr, nullptr, &eventInfo.macInfo);
            break;
        default:
            HKS_LOG_I("event id no need report!");
    }
    (void)HksFreshAndReport(funcName, processInfo, paramSet, info, &eventInfo);
    return HKS_SUCCESS;
}
