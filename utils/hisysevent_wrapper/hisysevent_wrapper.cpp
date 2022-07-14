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

#ifdef __cplusplus
extern "C" {
#endif

static constexpr const char *eventName = "HUKS_FAULT";
static constexpr const char *tagFunction = "FUNCTION";
static constexpr const char *tagUserId = "USER_ID";
static constexpr const char *tagProcessUID = "PROCESS_UID";
static constexpr const char *tagKeyType = "KEY_TYPE";
static constexpr const char *tagErrorCode = "ERROR_CODE";
static constexpr const char *tagExtra = "EXTRA";

static OHOS::HiviewDFX::HiSysEvent::EventType GetEventType(int32_t eventType)
{
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    switch (eventType)
    {
    case FAULT:
        /* code */
        type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
        break;
    case STATISTIC:
        type = OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC;
        break;
    case SECURITY:
        type = OHOS::HiviewDFX::HiSysEvent::EventType::SECURITY;
        break;
    case BEHAVIOR:
        type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
        break;
    default:
        break;
    }
    return type;
}

int WriteEvent(int32_t eventType, const char *functionName, struct EventValues *eventValues, const char *extra)
{
    return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY, eventName, GetEventType(eventType), tagFunction, functionName, 
        tagUserId, eventValues->userId, tagProcessUID, eventValues->processName, tagKeyType, eventValues->keyType, tagErrorCode, eventValues->errorCode, tagExtra, extra);
}

#ifdef __cplusplus
}
#endif