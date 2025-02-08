/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

static uint32_t removeSubstring(const char *format, char result[MAX_ERROR_MESSAGE_LEN])
{
    char *pos;
    int substringLen = strlen(LOG_PUBLIC);
    if (substringLen == 0) {
        HILOG_INFO(LOG_ENGINE, "nothing needs to be replaced");
        return HKS_FAILURE;
    }
    int i = 0;
    while ((pos = strstr(format, LOG_PUBLIC)) != NULL) {
        if (i >= MAX_ERROR_MESSAGE_LEN - 1) {
            HILOG_INFO(LOG_ENGINE, "error message is too long to fill in");
            break;
        }
        while (format < pos) {
            result[i++] = *format++;
        }
        format = pos + substringLen;
    }
    while (*format && i <= MAX_ERROR_MESSAGE_LEN - 1) {
        result[i++] = *format++;
    }
    result[i] = '\0';
    return HKS_SUCCESS;
}

void HksLog(uint32_t logLevel, const char *format, ...)
{
#ifndef LOG_PUBLIC
    return;
#endif
    va_list ap;

    if (g_msgLen == 0 || logLevel == HKS_LOG_LEVEL_E_IMPORTANT) {
        char newFormat[MAX_ERROR_MESSAGE_LEN] = {0};
        if (removeSubstring(format, newFormat) != HKS_SUCCESS) {
            HILOG_INFO(LOG_ENGINE, "skip to add errMsg");
            return;
        }
        va_start(ap, format);
        char buff[MAX_ERROR_MESSAGE_LEN] = {0};
        int32_t buffLen = vsnprintf_s(buff, MAX_ERROR_MESSAGE_LEN, MAX_ERROR_MESSAGE_LEN - 1, newFormat, ap);
        va_end(ap);
        if (buffLen < 0) {
            HILOG_ERROR(LOG_ENGINE, "[HksLog] vsnprintf_s fail! ret: %{public}d, newFormat:[%{public}s]", buffLen,
                newFormat);
            return;
        }
        if (g_msgLen + (uint32_t)buffLen >= MAX_ERROR_MESSAGE_LEN) {
            HILOG_INFO(LOG_ENGINE, "errMsg is almost full!");
            return;
        }

        if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN, buff, buffLen) != EOK) {
            HILOG_ERROR(LOG_ENGINE, "[HksLog] copy errMsg buff fail!");
            return;
        }
        g_msgLen += (uint32_t)buffLen;
    } else {
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
            HILOG_ERROR(LOG_ENGINE, "[HksLog] append call chain fail! offset: %d", offset);
            return;
        }
        g_msgLen += (uint32_t)offset;
    }
}

void PrintErrorMsg(void)
{
    if (g_msgLen != 0) {
        HILOG_ERROR(LOG_ENGINE, "[HksLog]: g_errMsg [%{public}s]", g_errMsg);
    }
}
#endif

