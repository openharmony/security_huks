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

#include <cstdint>
#include <string>
#include <sys/stat.h>
#include <ctime>
#include <unordered_map>

#include "hks_event_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_type_inner.h"
#include "securec.h"

static int32_t ThreeStageBuildCommonInfo(const struct HksParamSet *paramSet, struct HksEventInfo *eventInfo)
{
    struct HksParam *param = nullptr;
    if (HksGetParam(paramSet, HKS_TAG_PARAM3_BUFFER, &param) == HKS_SUCCESS) {
        if (param->blob.size < sizeof(HksEventInfo)) {
            HKS_LOG_I("blob size is less than eventInfo");
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
        *eventInfo = *reinterpret_cast<HksEventInfo *>(param->blob.data);
    } else {
        return HKS_FAILURE;
    }

    if (HksGetParam(paramSet, HKS_TAG_PARAM0_BUFFER, &param) == HKS_SUCCESS) {
        eventInfo->common.function = static_cast<char *>(HksMalloc(param->blob.size));
        HKS_IF_NULL_LOGI_RETURN(eventInfo->common.function, HKS_ERROR_MALLOC_FAIL, "malloc funcname fail")
        (void)memcpy_s(eventInfo->common.function, param->blob.size, param->blob.data, param->blob.size);
    }

    if (HksGetParam(paramSet, HKS_TAG_PARAM1_BUFFER, &param) == HKS_SUCCESS) {
        if (param->blob.size < sizeof(struct timespec)) {
            HKS_LOG_I("blob size is less than timespec");
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
        (void)memcpy_s(&eventInfo->common.time, param->blob.size, param->blob.data, param->blob.size);
    }

    if (HksGetParam(paramSet, HKS_TAG_PARAM2_BUFFER, &param) == HKS_SUCCESS) {
        eventInfo->common.callerInfo.name = static_cast<char *>(HksMalloc(param->blob.size));
        HKS_IF_NULL_LOGI_RETURN(eventInfo->common.callerInfo.name, HKS_ERROR_MALLOC_FAIL, "malloc processname fail")
        (void)memcpy_s(eventInfo->common.callerInfo.name, param->blob.size, param->blob.data, param->blob.size);
    }

    if (HksGetParam(paramSet, HKS_TAG_PARAM0_NULL, &param) == HKS_SUCCESS) {
        eventInfo->common.result.errMsg = static_cast<char *>(HksMalloc(param->blob.size));
        HKS_IF_NULL_LOGI_RETURN(eventInfo->common.result.errMsg, HKS_ERROR_MALLOC_FAIL, "malloc error msg fail")
        (void)memcpy_s((char *)eventInfo->common.result.errMsg, param->blob.size, param->blob.data, param->blob.size);
    }

    eventInfo->common.count = 1;
    return HKS_SUCCESS;
}

int32_t BuildCommonInfo(const struct HksParamSet *paramSet, struct HksEventInfo *eventInfo)
{
    if (paramSet == nullptr || eventInfo == nullptr) {
        HKS_LOG_I("paramset or eventInfo is null");
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = ThreeStageBuildCommonInfo(paramSet, eventInfo);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(eventInfo->common.function);
        HKS_FREE(eventInfo->common.callerInfo.name);
        HKS_FREE(eventInfo->common.result.errMsg);
    }
    return ret;
}

static bool CheckKeyInfo(const HksEventKeyInfo *keyInfo1, const HksEventKeyInfo *keyInfo2)
{
    return (keyInfo1->specificUserId == keyInfo2->specificUserId) && (keyInfo1->aliasHash == keyInfo2->aliasHash);
}

// check uid, operation, userId
bool CheckEventCommon(const struct HksEventInfo *info1, const struct HksEventInfo *info2)
{
    if ((info1 == nullptr) || (info2 == nullptr) ||
        (info1->common.callerInfo.uid != info2->common.callerInfo.uid) ||
        (info1->common.eventId != info2->common.eventId) ||
        (info1->common.operation != info2->common.operation)) {
        return false;
    }
    switch (info1->common.eventId) {
        case HKS_EVENT_CRYPTO:
            return CheckKeyInfo(&info1->cryptoInfo.keyInfo, &info2->cryptoInfo.keyInfo);
        case HKS_EVENT_AGREE_DERIVE:
            return CheckKeyInfo(&info1->agreeDeriveInfo.keyInfo, &info2->agreeDeriveInfo.keyInfo);
        case HKS_EVENT_MAC:
            return CheckKeyInfo(&info1->macInfo.keyInfo, &info2->macInfo.keyInfo);
        case HKS_EVENT_ATTEST:
            return CheckKeyInfo(&info1->attestInfo.keyInfo, &info2->attestInfo.keyInfo);
        default:
            return false;
    }
}

// add count, dataLen, totalCost
void AddEventInfoCommon(HksEventInfo *info1, const HksEventInfo *info2)
{
    if (info1 == nullptr || info2 == nullptr) {
        HKS_LOG_I("eventInfo is null");
        return;
    }
    info1->common.count++;
    if (!IsAdditionOverflow(info1->common.statInfo.dataLen, info2->common.statInfo.dataLen)) {
        info1->common.statInfo.dataLen += info2->common.statInfo.dataLen;
    }

    if (!IsAdditionOverflow(info1->common.statInfo.totalCost, info2->common.statInfo.totalCost)) {
        info1->common.statInfo.totalCost += info2->common.statInfo.totalCost;
    }
}

void KeyInfoToMap(const HksEventKeyInfo *keyInfo, std::unordered_map<std::string, std::string>& map)
{
    std::unordered_map<std::string, std::string> infoMap = {
        { "alias_hash", std::to_string(keyInfo->aliasHash) },
        { "storage_level", std::to_string(keyInfo->storageLevel) },
        { "specific_os_account_id", std::to_string(keyInfo->specificUserId) },
        { "algorithm", std::to_string(keyInfo->alg) },
        { "purpose", std::to_string(keyInfo->purpose) },
        { "key_size", std::to_string(keyInfo->keySize) },
        { "key_flag", std::to_string(keyInfo->keyFlag) },
        { "key_hash", std::to_string(keyInfo->keyHash) },
        { "batch_operation", std::to_string(keyInfo->isBatch) },
        { "batch_purpose", std::to_string(keyInfo->batchPur) },
        { "batch_timeout", std::to_string(keyInfo->batchTimeOut) },
    };

    for (auto info : infoMap) {
        map.insert_or_assign(info.first, info.second);
    }
}

void KeyAccessInfoToMap(const HksEventKeyAccessInfo *accessInfo, std::unordered_map<std::string, std::string>& map)
{
    std::unordered_map<std::string, std::string> infoMap = {
        { "auth_type", std::to_string(accessInfo->authType) },
        { "access_type", std::to_string(accessInfo->accessType) },
        { "challenge_type", std::to_string(accessInfo->challengeType) },
        { "challenge_pos", std::to_string(accessInfo->challengePos) },
        { "auth_timeout", std::to_string(accessInfo->authTimeOut) },
        { "auth_purpose", std::to_string(accessInfo->authPurpose) },
        { "front_os_account_id", std::to_string(accessInfo->frontUserId) },
        { "auth_mode", std::to_string(accessInfo->authMode) },
        { "need_pwd_set", std::to_string(accessInfo->needPwdSet) },
    };

    for (auto info : infoMap) {
        map.insert_or_assign(info.first, info.second);
    }
}

void CryptoInfoToMap(const HksEventCryptoInfo *cryptoInfo, std::unordered_map<std::string, std::string>& map)
{
    std::unordered_map<std::string, std::string> infoMap = {
        { "block_mode", std::to_string(cryptoInfo->blockMode) },
        { "padding", std::to_string(cryptoInfo->padding) },
        { "digest", std::to_string(cryptoInfo->digest) },
        { "mgf_digest", std::to_string(cryptoInfo->mgfDigest) },
        { "handle_id", std::to_string(cryptoInfo->handleId) },
    };

    for (auto info : infoMap) {
        map.insert_or_assign(info.first, info.second);
    }
}

void AgreeDeriveInfoToMap(const HksEventAgreeDeriveInfo *info, std::unordered_map<std::string, std::string>& map)
{
    std::unordered_map<std::string, std::string> infoMap = {
        { "iter_count", std::to_string(info->iterCnt) },
        { "storage_flag", std::to_string(info->storageFlag) },
        { "derive_key_size", std::to_string(info->keySize) },
        { "agree_pubkey_type", std::to_string(info->pubKeyType) },
        { "handle_id", std::to_string(info->handleId) },
    };

    for (auto info : infoMap) {
        map.insert_or_assign(info.first, info.second);
    }
}

void AttestInfoToMap(const HksEventAttestInfo *attestInfo, std::unordered_map<std::string, std::string>& map)
{
    std::unordered_map<std::string, std::string> infoMap = {
        { "is_annonymous_attest", std::to_string(attestInfo->isAnnonymous) },
        { "attest_cert_type", std::to_string(attestInfo->baseCertType) },
    };

    for (auto info : infoMap) {
        map.insert_or_assign(info.first, info.second);
    }
}
