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

#ifndef HKS_REPORT_UKEY_EVENT_H
#define HKS_REPORT_UKEY_EVENT_H

#ifdef __cplusplus
#include <unordered_map>
#endif

#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_event_info.h"
#include "hks_type_enum.h"

#define HKS_UKEY_REPORT_REGISTER 0
#define HKS_UKEY_REPORT_UNREGISTER 1
#define HKS_UKEY_REPORT_OPEN_HANDLE 0
#define HKS_UKEY_REPORT_CLOSE_HANDLE 1
#define UKEY_TIMEOUT 3000 // ms

typedef struct UKeyInfo {
    uint32_t eventId;
    uint32_t operation;
    int32_t state;
    struct HksBlob providerName;
    struct HksBlob resourceId;
    struct HksBlob propertyId;
    struct HksBlob abilityName;
    struct HksBlob extBundleName;
    uint32_t alg;
    uint32_t purpose;
    uint32_t detailErrcode;
    struct HksBlob handle;
    struct HksBlob extraData;
} UKeyInfo;

typedef struct UKeyCommonInfo {
    int32_t returnCode;
    uint64_t startTime;
} UKeyCommonInfo;

/* register/ungister provider */
int32_t HksRegProviderParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksRegProviderNeedReport(const struct HksEventInfo *eventInfo);

bool HksRegProviderEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForRegProvider(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* get auth pin state */
int32_t HksGetAuthPinStateParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo);

bool HksGetAuthPinStateNeedReport(const struct HksEventInfo *eventInfo);

bool HksGetAuthPinStateEventInfoEqual(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForGetAuthPinState(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* auth pin */
int32_t HksAuthPinParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksAuthPinNeedReport(const struct HksEventInfo *eventInfo);

bool HksAuthPinEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForAuthPin(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* operate remote handle */
int32_t HksRemoteHandleParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksRemoteHandleNeedReport(const struct HksEventInfo *eventInfo);

bool HksRemoteHandleEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForRemoteHandle(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* export provider certificates */
int32_t HksExportProviderCertParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo);

bool HksExportProviderCertNeedReport(const struct HksEventInfo *eventInfo);

bool HksExportProviderCertEventInfoEqual(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForExportProviderCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* export certificates */
int32_t HksExportCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksExportCertNeedReport(const struct HksEventInfo *eventInfo);

bool HksExportCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForExportCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* get remote property */
int32_t HksGetPropertyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksGetPropertyNeedReport(const struct HksEventInfo *eventInfo);

bool HksGetPropertyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForGetProperty(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* import cert */
int32_t HksImportCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksImportCertNeedReport(const struct HksEventInfo *eventInfo);

bool HksImportCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForImportCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* get resource id */
int32_t HksGetResourceIdParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksGetResourceIdNeedReport(const struct HksEventInfo *eventInfo);

bool HksGetResourceIdEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForGetResourceId(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* clear pin state */
int32_t HksClearPinStateParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksClearPinStateNeedReport(const struct HksEventInfo *eventInfo);

bool HksClearPinStateEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForClearPinState(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* init session */
int32_t HksInitSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksInitSessionNeedReport(const struct HksEventInfo *eventInfo);

bool HksInitSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForInitSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* update session */
int32_t HksUpdateSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksUpdateSessionNeedReport(const struct HksEventInfo *eventInfo);

bool HksUpdateSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForUpdateSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* finish session */
int32_t HksFinishSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksFinishSessionNeedReport(const struct HksEventInfo *eventInfo);

bool HksFinishSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForFinishSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* abort session */
int32_t HksAbortSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksAbortSessionNeedReport(const struct HksEventInfo *eventInfo);

bool HksAbortSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForAbortSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* generate key */
int32_t HksGenerateKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksGenerateKeyNeedReport(const struct HksEventInfo *eventInfo);

bool HksGenerateKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForGenerateKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* export public key */
int32_t HksExportPublicKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksExportPublicKeyNeedReport(const struct HksEventInfo *eventInfo);

bool HksExportPublicKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForExportPublicKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* import wrapped key */
int32_t HksImportWrappedKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksImportWrappedKeyNeedReport(const struct HksEventInfo *eventInfo);

bool HksImportWrappedKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForImportWrappedKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

/* set remote property */
int32_t HksSetPropertyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

bool HksSetPropertyNeedReport(const struct HksEventInfo *eventInfo);

bool HksSetPropertyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForSetProperty(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

#ifdef __cplusplus
int32_t HksGetAuthPinStateEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksRegProviderEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksAuthPinEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksRemoteHandleEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksExportProviderCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksExportCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksGetPropertyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksImportCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksGetResourceIdEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksClearPinStateEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksInitSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksUpdateSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksFinishSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksAbortSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksGenerateKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksExportPublicKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksImportWrappedKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

int32_t HksSetPropertyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);
#endif

#ifdef __cplusplus
extern "C" {
#endif
int32_t ReportUKeyEvent(const struct UKeyInfo* ukeyInfo, const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct UKeyCommonInfo *ukeyCommon);

typedef struct UKeyReportErrInfo {
    int32_t ret;
    int32_t errVal;
} UKeyReportErrInfo;

void ReportUKeySessionEvent(uint32_t eventId, const struct UKeyReportErrInfo *errInfo,
    const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet);

void ReportUKeyKeyEvent(uint32_t eventId, const struct UKeyReportErrInfo *errInfo,
    const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet);

#ifdef __cplusplus
}
#endif

#endif