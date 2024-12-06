/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifdef L2_STANDARD

#include "hks_error_msg.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "hks_mem.h"
#include "securec.h"
#include "hks_log.h"

static __thread uint32_t g_msgLen = 0;
static __thread char g_errMsg[MAX_ERROR_MESSAGE_LEN + 1];

uint32_t HksGetThreadErrorMsgLen(void)
{
    return g_msgLen;
}

const char *HksGetThreadErrorMsg(void)
{
    return g_errMsg;
}

void HksClearThreadErrorMsg(void)
{
    (void)memset_s(g_errMsg, MAX_ERROR_MESSAGE_LEN + 1, 0, MAX_ERROR_MESSAGE_LEN + 1);
    g_msgLen = 0;
}

void HksAppendThreadErrMsg(const uint8_t *buff, uint32_t buffLen)
{
    if (g_msgLen + buffLen >= MAX_ERROR_MESSAGE_LEN) {
        HILOG_ERROR(LOG_ENGINE, "[HksLog] HksAppendThreadErrMsg: buff will overflow!"
            "g_msgLen = %{public}u, buffLen = %{public}u", g_msgLen, buffLen);
        return;
    }
    if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, buff, buffLen) != EOK) {
        HILOG_ERROR(LOG_ENGINE, "[HksLog] HksAppendThreadErrMsg: memcpy_s fail!"
            "g_msgLen = %{public}u, buffLen = %{public}u", g_msgLen, buffLen);
        return;
    }
    g_msgLen += buffLen;
}

static void UseHiLog(uint32_t logLevel, const char *log)
{
    switch (logLevel) {
        case HKS_LOG_LEVEL_I:
            HILOG_INFO(LOG_ENGINE, "%{public}s", log);
            break;
        case HKS_LOG_LEVEL_E:
            HILOG_ERROR(LOG_ENGINE, "%{public}s", log);
            break;
        case HKS_LOG_LEVEL_W:
            HILOG_WARN(LOG_ENGINE, "%{public}s", log);
            break;
        case HKS_LOG_LEVEL_D:
            HILOG_DEBUG(LOG_ENGINE, "%{public}s", log);
            break;
        default:
            HILOG_ERROR(LOG_ENGINE, "[HksLog] Error Log Level: %{public}s", log);
            break;
    }
}

void HksLog(uint32_t logLevel, const char *format, ...)
{
    char buff[MAX_ERROR_MESSAGE_LEN] = {0};
    va_list ap;
    va_start(ap, format);
    int32_t buffLen = vsnprintf_s(buff, MAX_ERROR_MESSAGE_LEN, MAX_ERROR_MESSAGE_LEN - 1, format, ap);
    va_end(ap);
    if (buffLen < 0) {
        HILOG_ERROR(LOG_ENGINE, "[HksLog] vsnprintf_s fail! ret: %{public}d, format:[%{public}s]", buffLen, format);
        return;
    }
    UseHiLog(logLevel, buff);

    if (logLevel != HKS_LOG_LEVEL_E || (g_msgLen + buffLen >= MAX_ERROR_MESSAGE_LEN)) { // donot need record
        return;
    }

    if (g_msgLen != 0) { // append call chain
        va_start(ap, format);
        char *funName = va_arg(ap, char *);
        uint32_t lineNo = va_arg(ap, uint32_t);
        va_end(ap);

        if (funName == NULL) {
            HILOG_ERROR(LOG_ENGINE, "[HksLog] get funName fail!");
            return;
        }
        int32_t offset = sprintf_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, " <%s[%u]",
            funName, lineNo);
        if (offset <= 0) {
            HILOG_ERROR(LOG_ENGINE, "[HksLog] append call chain fail!");
            return;
        }
        g_msgLen += offset;
    } else {
        if (memcpy_s(g_errMsg, MAX_ERROR_MESSAGE_LEN, buff, buffLen) != EOK) {
            HILOG_ERROR(LOG_ENGINE, "[HksLog] copy errMsg buff fail!");
            return;
        }
        g_msgLen = buffLen;
    }
}

void PrintErrorMsg(void)
{
    if (g_msgLen == 0) {
        HILOG_INFO(LOG_ENGINE, "[HksLog]: g_errMsg is empty");
    } else {
        HILOG_ERROR(LOG_ENGINE, "[HksLog]: g_errMsg [%{public}s]", g_errMsg);
    }
}
#endif

