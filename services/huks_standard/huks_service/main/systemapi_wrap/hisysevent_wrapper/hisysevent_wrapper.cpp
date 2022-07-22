/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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


#include "hisysevent_wrapper.h"
#include "hisysevent.h"

#include "hks_log.h"

#ifdef __cplusplus
extern "C" {
#endif

static constexpr const char g_eventName[] = "HUKS_FAULT";
static constexpr const char g_tagFunction[] = "FUNCTION";
static constexpr const char g_tagUserId[] = "USER_ID";
static constexpr const char g_tagProcessUID[] = "PROCESS_UID";
static constexpr const char g_tagKeyType[] = "KEY_TYPE";
static constexpr const char g_tagErrorCode[] = "ERROR_CODE";
static constexpr const char g_tagExtra[] = "EXTRA";

static int32_t ConvertToHiSysEventType(enum EventType inEventType, 
    enum OHOS::HiviewDFX::HiSysEvent::EventType *outEventType)
{
    switch (inEventType) {
        case FAULT:
            *outEventType = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
            break;
        case STATISTIC:
            *outEventType = OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC;
            break;
        case SECURITY:
            *outEventType = OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY;
            break;
        case BEHAVIOR:
            *outEventType = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
            break;
        default:
            HKS_LOG_E("Invalid inEventType!");
            return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int WriteEvent(enum EventType eventType, const char *functionName, const struct EventValues *eventValues,
    const char *extra)
{
    enum OHOS::HiviewDFX::HiSysEvent::EventType outEventType;
    int32_t ret;
    ret = ConvertToHiSysEventType(eventType, &outEventType);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("convert to hiSysEvent event type failed!");
        return ret;
    }
    return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY, g_eventName,
        outEventType, g_tagFunction, functionName, g_tagUserId, eventValues->userId, g_tagProcessUID,
        eventValues->processName, g_tagKeyType, eventValues->keyType, g_tagErrorCode, eventValues->errorCode,
        g_tagExtra, extra);
}

#ifdef __cplusplus
}
#endif