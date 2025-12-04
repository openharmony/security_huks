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

#ifndef HKS_EVENT_INFO_H
#define HKS_EVENT_INFO_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "hks_type_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

// modify this please sync modify g_threeStageEvent
enum HksEventId {
    HKS_EVENT_CRYPTO = 1,
    HKS_EVENT_SIGN_VERIFY = 2,
    HKS_EVENT_DERIVE = 3,
    HKS_EVENT_AGREE = 4,
    HKS_EVENT_MAC = 5,
    HKS_EVENT_ATTEST = 6,
    HKS_EVENT_GENERATE_KEY = 7,
    HKS_EVENT_CHECK_KEY_EXISTED = 8,
    HKS_EVENT_DELETE_KEY = 9,
    HKS_EVENT_IMPORT_KEY = 10,
    HKS_EVENT_LIST_ALIASES = 11,
    HKS_EVENT_RENAME_KEY = 12,
    HKS_EVENT_GET_PROPERTIES = 13,
    HKS_EVENT_KEY_LEVEL_CHANGE = 14,
    /* closed source event start with 15, end with 19 */
    HKS_EVENT_DATA_SIZE_STATISTICS = 30,
    // ukey events
    HKS_EVENT_UKEY_START = 31,
    HKS_EVENT_UKEY_REGISTER_PROVIDER = HKS_EVENT_UKEY_START,
    HKS_EVENT_UKEY_GET_AUTH_PIN_STATE = 32,
    HKS_EVENT_UKEY_AUTH_PIN = 33,
    HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE = 34,
    HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT = 35,
    HKS_EVENT_UKEY_EXPORT_CERT = 36,
    HKS_EVENT_UKSY_GET_REMOTE_PROPERTY = 37,
    HKS_EVENT_UKEY_END = HKS_EVENT_UKSY_GET_REMOTE_PROPERTY
};

// modify this please sync modify g_threeStage
enum HksReportStage {
    HKS_INIT = 1,
    HKS_UPDATE = 2,
    HKS_FINISH = 3,
    HKS_ABORT = 4,
    HKS_ONE_STAGE = 5,
    HKS_ONE_STAGE_CRYPTO = 6,
    HKS_ONE_STAGE_SIGN_VERIFY = 7,
    HKS_ONE_STAGE_DERIVE = 8,
    HKS_ONE_STAGE_AGREE = 9,
    HKS_ONE_STAGE_MAC = 10,
    HKS_ONE_STAGE_ATTEST = 11,
};

#define IF_UKEY_EVENT(eventId) ((eventId) >= HKS_EVENT_UKEY_START && (eventId) <= HKS_EVENT_UKEY_END)

typedef struct HksEventKeyAccessInfo {
    uint32_t authType;
    uint32_t accessType;
    uint32_t challengeType;
    uint32_t challengePos;
    uint32_t authTimeOut;
    uint32_t authPurpose;
    uint32_t frontUserId;
    uint32_t authMode;
    uint32_t needPwdSet;
} HksEventKeyAccessInfo;

typedef struct HksEventKeyInfo {
    uint32_t storageLevel;
    int32_t specificUserId;
    uint32_t alg;
    uint32_t purpose;
    uint32_t keySize;
    uint32_t keyFlag;
    uint16_t keyHash;
    uint8_t aliasHash;
    bool isBatch;
    uint32_t batchPur;
    uint32_t batchTimeOut;
} HksEventKeyInfo;

typedef struct HksEventStatInfo {
    uint32_t saCost;
    uint32_t ca2taCost;
    uint32_t taCost;
    uint32_t gpCost;
    uint32_t initCost;
    uint32_t updateCost;
    uint32_t updateCount;
    uint32_t finishCost;
    uint32_t totalCost;
    uint32_t dataLen;
} HksEventStatInfo;

typedef struct HksEventResultInfo {
    int32_t code;
    uint32_t module;
    uint32_t stage;
    char *errMsg;
} HksEventResultInfo;

typedef struct HksEventCallerInfo {
    uint32_t uid;
    char *name;
} HksEventCallerInfo;

typedef struct HksEventCommonInfo {
    uint64_t traceId;
    struct timespec time;
    HksEventCallerInfo callerInfo;
    HksEventResultInfo result;
    HksEventStatInfo statInfo;
    uint32_t eventId;
    uint32_t operation;
    uint32_t count;
    char *function;
} HksEventCommonInfo;

typedef struct HksEventCryptoInfo {
    HksEventKeyInfo keyInfo;
    HksEventKeyAccessInfo accessCtlInfo;
    uint32_t blockMode;
    uint32_t padding;
    uint32_t digest;
    uint32_t mgfDigest;
    uint32_t handleId;
} HksEventCryptoInfo;

typedef struct HksEventAgreeDeriveInfo {
    HksEventKeyInfo keyInfo;
    HksEventKeyAccessInfo accessCtlInfo;
    uint32_t iterCnt;
    uint32_t storageFlag;
    uint32_t keySize;
    uint32_t pubKeyType;
    uint32_t handleId;
} HksEventAgreeDeriveInfo;

typedef struct HksEventMacInfo {
    HksEventKeyInfo keyInfo;
    HksEventKeyAccessInfo accessCtlInfo;
    uint32_t handleId;
} HksEventMacInfo;

typedef struct HksEventAttestInfo {
    HksEventKeyInfo keyInfo;
    uint32_t baseCertType;
    uint32_t isAnonymous;
} HksEventAttestInfo;

typedef struct GenerateInfo {
    struct HksEventKeyInfo keyInfo;
    struct HksEventKeyAccessInfo keyAccessInfo;
    uint32_t agreeAlg;
    uint32_t pubKeyIsAlias;
} GenerateInfo;

typedef struct ImportInfo {
    struct HksEventKeyInfo keyInfo;
    struct HksEventKeyAccessInfo keyAccessInfo;
    uint32_t keyType;
    uint32_t algSuit;
} ImportInfo;

typedef struct RenameInfo {
    struct HksEventKeyInfo keyInfo;
    uint8_t dstAliasHash;
    bool isCopy;
} RenameInfo;

typedef struct DataSizeInfo {
    char *component;
    char *partition;
    char *foldPath;
    char *foldSize;
    uint64_t partitionRemain;
} DataSizeInfo;

typedef struct UKeyEventInfo {
    int32_t callAuthUid;
    int32_t state;
    int32_t purpose;
    char *providerName;
    char *abilityName;
    char *resourceId;
    char *propertyId;
} UKeyEventInfo;

typedef struct HksEventInfo {
    struct HksEventCommonInfo common;
    union {
        HksEventKeyInfo keyInfo;
        HksEventKeyAccessInfo keyAccessInfo;
        HksEventCryptoInfo cryptoInfo;
        HksEventAgreeDeriveInfo agreeDeriveInfo;
        HksEventMacInfo macInfo;
        HksEventAttestInfo attestInfo;
        GenerateInfo generateInfo;
        ImportInfo importInfo;
        RenameInfo renameInfo;
        DataSizeInfo dataSizeInfo;
        UKeyEventInfo ukeyInfo;
    };
} HksEventInfo;

#ifdef __cplusplus
}
#endif

#endif  // HKS_EVENT_INFO_H
