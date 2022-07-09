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

// int WriteEvent(void)
// {
//     std::string TEST = "TEST";
//     constexpr const char *name = "NAME1";
//     std::string value = "value";
//     return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY, TEST, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, name, value);
// }

constexpr const char *eventName = "HUKS_ERROR";
constexpr const char *tagFunction = "FUNCTION";
constexpr const char *tagUserId = "USER_ID";
constexpr const char *tagProcessName = "PROCESS_NAME";
constexpr const char *tagKeyType = "KEY_TYPE";
constexpr const char *tagErrorCode = "ERROR_CODE";
constexpr const char *tagExtra = "EXTRA";

int WriteEvent(const char *functionName, struct EventValues *eventValues, const char *extra)
{

    return OHOS::HiviewDFX::HiSysEvent::Write(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY, eventName, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, 
        tagFunction, functionName, tagUserId, eventValues->userId, tagProcessName, eventValues->processName, tagKeyType, eventValues->keyType, tagErrorCode, eventValues->errorCode, tagExtra, extra);
}

#ifdef __cplusplus
}
#endif