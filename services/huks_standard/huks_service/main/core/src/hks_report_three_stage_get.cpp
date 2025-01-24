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
#include <stdint.h>
#include <string>
#include <sys/stat.h>
#include <time.h>

#include "hks_api.h"
#include "hks_error_msg.h"
#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_report.h"
#include "hks_report_common.h"
#include "hks_session_manager.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "hks_util.h"
#include "time.h"

static int32_t GetEventId(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGE_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null");

    struct HksParam *purposeParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_PURPOSE, &purposeParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get purpose param fail")
    eventInfo->common.operation = purposeParam->uint32Param;

    switch (purposeParam->uint32Param) {
        case HKS_KEY_PURPOSE_ENCRYPT:
        case HKS_KEY_PURPOSE_DECRYPT:
        case HKS_KEY_PURPOSE_SIGN:
        case HKS_KEY_PURPOSE_VERIFY:
            eventInfo->common.eventId = HKS_EVENT_CRYPTO;
            eventInfo->cryptoInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_AGREE:
        case HKS_KEY_PURPOSE_DERIVE:
            eventInfo->common.eventId = HKS_EVENT_AGREE_DERIVE;
            eventInfo->agreeDeriveInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        case HKS_KEY_PURPOSE_MAC:
            eventInfo->common.eventId = HKS_EVENT_MAC;
            eventInfo->macInfo.keyInfo.purpose = purposeParam->uint32Param;
            break;
        default:
        HKS_LOG_E("purpose no need report");
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

static void GetKeyAccessInfo(const struct HksParamSet *paramSet, HksEventKeyAccessInfo *info)
{
    struct HksParam *param = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_USER_AUTH_TYPE, &param);
    if (ret != HKS_SUCCESS) {
        return;
    }
    info->authType = param->uint32Param;
    HKS_LOG_I("get auth type param succ");

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

static void GetKeyInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias, HksEventKeyInfo *keyInfo)
{
    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &param) == HKS_SUCCESS) {
        keyInfo->storageLevel = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &param) == HKS_SUCCESS) {
        keyInfo->specificUserId = param->uint32Param;
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
        uint8_t aliasHash = 0;
        (void)GetKeyAliasHash(keyAlias, &aliasHash);
        keyInfo->aliasHash = aliasHash;
    }
}

static void GetCryptoInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    HksEventCryptoInfo *cryptoInfo)
{
    GetKeyInfo(paramSet, keyAlias, &cryptoInfo->keyInfo);
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
    HksEventAgreeDeriveInfo *info)
{
    GetKeyInfo(paramSet, keyAlias, &info->keyInfo);
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

static void GetMacInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias, HksEventMacInfo *macInfo)
{
    GetKeyInfo(paramSet, keyAlias, &macInfo->keyInfo);
    GetKeyAccessInfo(paramSet, &macInfo->accessCtlInfo);
}

static void GetAttestInfo(const struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    HksEventAttestInfo *attestInfo)
{
    GetKeyInfo(paramSet, keyAlias, &attestInfo->keyInfo);

    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_CERT_TYPE, &param) == HKS_SUCCESS) {
        attestInfo->baseCertType = param->uint32Param;
    }

    if (HksGetParam(paramSet, HKS_TAG_ATTESTATION_MODE, &param) == HKS_SUCCESS) {
        attestInfo->isAnnonymous = param->uint32Param;
    }
}

int32_t HksGetAttestEventInfo(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksEventInfo *eventInfo)
{
    eventInfo->common.eventId = HKS_EVENT_ATTEST;
    eventInfo->common.callerInfo.uid = processInfo->uidInt;

    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_PURPOSE, &param) == HKS_SUCCESS) {
        eventInfo->common.operation = param->uint32Param;
        eventInfo->attestInfo.keyInfo.purpose = param->uint32Param;
    }

    HKS_IF_NULL_LOGE_RETURN(key->data, HKS_ERROR_NULL_POINTER, "key is null")
    struct HksParamSet *keyBlobParamSet = (struct HksParamSet *)key->data;

    GetAttestInfo(paramSet, keyAlias, &(eventInfo->attestInfo));
    GetAttestInfo(keyBlobParamSet, keyAlias, &(eventInfo->attestInfo));
    return HKS_SUCCESS;
}

int32_t HksGetInitEventInfo(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksEventInfo *eventInfo)
{
    int32_t ret = GetEventId(paramSet, eventInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get event id fail")
    eventInfo->common.callerInfo.uid = processInfo->uidInt;

    HKS_IF_NULL_LOGE_RETURN(key->data, HKS_ERROR_NULL_POINTER, "key is null")
    struct HksParamSet *keyBlobParamSet = (struct HksParamSet *)key->data;

    struct HksParam *param = nullptr;
    if (HksGetParam(keyBlobParamSet, HKS_TAG_ACCESS_TOKEN_ID, &param) == HKS_SUCCESS) {
        if (processInfo->accessTokenId != param->uint64Param) {
            // access token id is not sensitive information, no risk
            HKS_LOG_E_IMPORTANT("token id mismatch, process token id = %" LOG_PUBLIC "llu, key token id = %" LOG_PUBLIC
                "llu", processInfo->accessTokenId, param->uint64Param);
        }
    }

    switch (eventInfo->common.eventId) {
        case HKS_EVENT_CRYPTO:
            GetCryptoInfo(paramSet, keyAlias, &eventInfo->cryptoInfo);
            GetCryptoInfo(keyBlobParamSet, keyAlias, &eventInfo->cryptoInfo);
            break;
        case HKS_EVENT_AGREE_DERIVE:
            GetAgreeDeriveInfo(paramSet, keyAlias, &eventInfo->agreeDeriveInfo);
            GetAgreeDeriveInfo(keyBlobParamSet, keyAlias, &eventInfo->agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, keyAlias, &eventInfo->macInfo);
            GetMacInfo(keyBlobParamSet, keyAlias, &eventInfo->macInfo);
            break;
        default:
            HKS_LOG_E("event id no need report");
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

static void FreshEventInfo(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    switch (eventInfo->common.eventId) {
        case HKS_EVENT_CRYPTO:
            GetCryptoInfo(paramSet, nullptr, &eventInfo->cryptoInfo);
            break;
        case HKS_EVENT_AGREE_DERIVE:
            GetAgreeDeriveInfo(paramSet, nullptr, &eventInfo->agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, nullptr, &eventInfo->macInfo);
            break;
        default:
            HKS_LOG_E("event id no need report!");
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
        cost = (uint32_t)(endTime - startTime);
    }

    switch (stage) {
        case HKS_INIT:
            statInfo->initCost = cost;
        case HKS_UPDATE:
            if (!IsAdditionOverflow(statInfo->updateCost, cost)) {
                statInfo->updateCost += cost;
            }
            statInfo->updateCount++;
        case HKS_FINISH:
            statInfo->finishCost = cost;
            break;
        case HKS_ABORT:
            break;
        default:
            break;
    }
}

int32_t HksServiceInitReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, HksEventInfo *eventInfo)
{
    if (info->errCode == HKS_SUCCESS) {
        struct HksOperation *operation = QueryOperationAndMarkInUse(processInfo, info->handle);
        HKS_IF_NULL_LOGE_RETURN(operation, HKS_ERROR_NOT_EXIST, "operation is not exist or busy in init report")

        operation->eventInfo = *eventInfo;
        FreshStatInfo(&(eventInfo->common.statInfo), info->inDataSize, info->stage, info->startTime);
        MarkOperationUnUse(operation);
        return HKS_SUCCESS;
    }
    HksFreshAndReport(funcName, processInfo, paramSet, info, eventInfo);
    return HKS_SUCCESS;
}

int32_t HksFreshAndReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGE_RETURN(info, HKS_ERROR_NULL_POINTER, "info is null")
    HKS_IF_NULL_LOGE_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "event info is null")

    if (info->stage != HKS_ONE_STAGE) {
        FreshEventInfo(paramSet, eventInfo);
        FreshStatInfo(&(eventInfo->common.statInfo), info->inDataSize, info->stage, info->startTime);
    }

    if (info->errCode == HKS_SUCCESS && (info->stage == HKS_INIT || info->stage == HKS_UPDATE)) {
        return HKS_SUCCESS;
    }

    struct timespec curTime;
    int32_t ret = clock_gettime(CLOCK_MONOTONIC, &curTime);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_FAILURE, "clock get time fail")

    const char *errorMsg = HksGetThreadErrorMsg();
    HKS_IF_NULL_LOGE_RETURN(errorMsg, HKS_ERROR_NULL_POINTER, "get error msg fail")

    struct HksParamSet *reportParamSet = nullptr;
    ret = HksInitParamSet(&reportParamSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init report paramset fail")

    do {
        HksEventResultInfo result = { .code = info->errCode, .stage = info->stage, .module = 0, .errMsg = nullptr };
        eventInfo->common.result = result;
        std::string callerName;
        ret = ReportGetCallerName(callerName);
        const struct HksParam params[] = {
            { .tag = HKS_TAG_PARAM0_UINT32, .uint32Param = eventInfo->common.eventId },
            { .tag = HKS_TAG_PARAM0_BUFFER, .blob = { strlen(funcName) + 1, (uint8_t *)funcName } },
            { .tag = HKS_TAG_PARAM1_BUFFER, .blob = { sizeof(struct timespec), (uint8_t *)&curTime } },
            { .tag = HKS_TAG_PARAM2_BUFFER, .blob = { callerName.size() + 1, (uint8_t *)callerName.c_str() } },
            { .tag = HKS_TAG_PARAM3_BUFFER, .blob = { sizeof(HksEventInfo), (uint8_t *)eventInfo } },
            { .tag = HKS_TAG_PARAM0_NULL, .blob = { strlen(errorMsg) + 1, (uint8_t *)errorMsg } },
        };

        ret = HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add params fail")

        ret = HksBuildParamSet(&reportParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "build paramset fail")

        HKS_LOG_I("three stage report %" LOG_PUBLIC "s, purpose = %" LOG_PUBLIC "d, eventId = %" LOG_PUBLIC "d",
            funcName, eventInfo->common.operation, eventInfo->common.eventId);
        HksEventReport(funcName, processInfo, paramSet, reportParamSet, info->errCode);
    } while (0);

    HksFreeParamSet(&reportParamSet);
    return ret;
}

int32_t HksThreeStageReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, struct HksOperation *operation)
{
    HKS_IF_NULL_LOGE_RETURN(info, HKS_ERROR_NULL_POINTER, "three stage report info is null")

    if (operation != nullptr) {
        (void)HksFreshAndReport(funcName, processInfo, paramSet, info, &operation->eventInfo);
        return HKS_SUCCESS;
    }

    HksEventInfo eventInfo {};
    int32_t ret = GetEventId(paramSet, &eventInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get event id fail")
    eventInfo.common.callerInfo.uid = processInfo->uidInt;

    switch (eventInfo.common.eventId) {
        case HKS_EVENT_CRYPTO:
            GetCryptoInfo(paramSet, nullptr, &eventInfo.cryptoInfo);
            break;
        case HKS_EVENT_AGREE_DERIVE:
            GetAgreeDeriveInfo(paramSet, nullptr, &eventInfo.agreeDeriveInfo);
            break;
        case HKS_EVENT_MAC:
            GetMacInfo(paramSet, nullptr, &eventInfo.macInfo);
            break;
        default:
            HKS_LOG_E("event id no need report!");
    }
    (void)HksFreshAndReport(funcName, processInfo, paramSet, info, &eventInfo);
    return HKS_SUCCESS;
}
